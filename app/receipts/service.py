"""脱敏签证的构建、原子发布与台账幂等。

- 构建：读取原始回单 -> 逐行脱敏（原件不变）-> 文档摘要。
- 台账：(visa_no, source_sha256) 唯一；同一回单对同一签证重试不新增、不重建。
- 发布：单事务写入签证版本并切换发布指针；任何步骤失败整体回滚，
  旧发布指针保持不变；失败单独留痕（visa_attempts）。
"""
import hashlib,json
from app.config import RULE_VERSION
from app.errors import DomainError
from app.receipts import storage
from app.receipts.masking import mask_receipt,sha256_hex,recompute_line_digest,verify_tokens
from app.receipts.secret import load_secret

def _secret(): return load_secret(storage.DATA_DIR)

def build(period,role):
    storage.audit(role,"build",{"period":period})
    receipts=storage.list_receipts()
    if not receipts: raise DomainError("NO_RECEIPT","没有可纳入签证的回单，请先导入")
    secret=_secret()
    rows=[]
    for r in receipts:
        masked=mask_receipt(r["payload"],secret)
        masked["receipt_no"]=r["receipt_no"]
        masked["source_sha256"]=r["source_sha256"]
        # 溯源字段补齐后重算行摘要，保证发布内容与公开核验口径一致
        masked["line_digest"]=recompute_line_digest(masked)
        rows.append(masked)
    rows.sort(key=lambda x:x["receipt_no"])
    input_sha256=hashlib.sha256("".join(r["source_sha256"] for r in rows).encode()).hexdigest()
    document_digest=sha256_hex({"rule_version":RULE_VERSION,"period":period,
                                "input_sha256":input_sha256,"rows":rows})
    return {"period":period,"input_sha256":input_sha256,"rule_version":RULE_VERSION,
            "document_digest":document_digest,"rows":rows,
            "receipt_count":len(rows)}

def publish(period,role,fail_after_write=False):
    """返回 (签证, 动作)；动作为 created 或 reused（重试幂等）。"""
    # 先在事务外完成脱敏计算，避免长事务
    draft=build(period,role)
    visa_no=storage.next_visa_no(period)
    attempted_visa_no=visa_no
    db=storage.connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        if fail_after_write:
            # 故障注入在台账短路之前，保证“已发布后再次发布失败”也能验证旧版保留
            raise RuntimeError("模拟发布失败：进入事务后中断")
        # 台账幂等：任一来源回单已挂到同号签证，则直接复用已发布版本，不新增
        for row in draft["rows"]:
            hit=db.execute("SELECT visa_no FROM visa_ledger WHERE source_sha256=?",
                           (row["source_sha256"],)).fetchone()
            if hit:
                existing_visa_no=hit["visa_no"]
                prior=db.execute("SELECT version FROM visa_publications WHERE visa_no=?",
                                 (existing_visa_no,)).fetchone()
                db.rollback()
                if not prior:
                    raise DomainError("LEDGER_STATE","台账存在未完成签证，请联系财务核对",409)
                return storage.get_published(existing_visa_no),"reused"
        prior_pub=db.execute("SELECT visa_no,version FROM visa_publications ORDER BY published_at DESC LIMIT 1").fetchone()
        next_version=(prior_pub["version"]+1) if prior_pub else 1
        cur=db.execute(
            "INSERT INTO visas(visa_no,period,version,document_digest,input_sha256,rule_version,rows_json,created_by,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (visa_no,period,next_version,draft["document_digest"],draft["input_sha256"],
             RULE_VERSION,json.dumps(draft["rows"],ensure_ascii=False),role,storage.now_iso()))
        visa_id=cur.lastrowid
        if prior_pub:
            db.execute("DELETE FROM visa_publications WHERE visa_no=?",(prior_pub["visa_no"],))
        db.execute("INSERT INTO visa_publications(visa_no,active_visa_id,version,published_at) VALUES(?,?,?,?)",
                   (visa_no,visa_id,next_version,storage.now_iso()))
        for row in draft["rows"]:
            db.execute("INSERT INTO visa_ledger(visa_no,source_sha256) VALUES(?,?)",
                       (visa_no,row["source_sha256"]))
        db.commit()
    except Exception as exc:
        db.rollback()
        reason=str(exc)
        with storage.connect() as log_db:
            log_db.execute("INSERT INTO visa_attempts(visa_no,version,result,reason,created_at) VALUES(?,?,?,?,?)",
                           (attempted_visa_no,0,"failed",reason,storage.now_iso()))
        if isinstance(exc,DomainError): raise
        raise DomainError("PUBLISH_FAILED","发布失败，已回滚，旧版签证保持有效",500)
    finally:
        db.close()
    with storage.connect() as log_db:
        log_db.execute("INSERT INTO visa_attempts(visa_no,version,result,reason,created_at) VALUES(?,?,?,?,?)",
                       (visa_no,next_version,"published",None,storage.now_iso()))
    storage.audit(role,"publish",{"visa_no":visa_no,"version":next_version,
                                  "receipts":len(draft["rows"])},visa_no=visa_no)
    return storage.get_published(visa_no),"created"

def verify(visa):
    """无密钥公开核验：只重算行摘要与文档摘要，不接触原件。"""
    rows=visa["rows"]
    line_results=[{"receipt_no":r["receipt_no"],
                   "line_digest_ok":recompute_line_digest(r)==r["line_digest"]} for r in rows]
    rebuilt_digest=sha256_hex({"rule_version":visa["rule_version"],"period":visa["period"],
                               "input_sha256":visa["input_sha256"],"rows":rows})
    return {"line_checks":line_results,
            "lines_ok":all(x["line_digest_ok"] for x in line_results),
            "document_digest_ok":rebuilt_digest==visa["document_digest"],
            "document_digest":visa["document_digest"]}

def traceback(visa,receipt_no,role):
    """持密钥回查：用原件重算 HMAC 令牌，证明脱敏行可回到指定原始回单。"""
    target=next((r for r in visa["rows"] if r["receipt_no"]==receipt_no),None)
    if not target: raise DomainError("NOT_FOUND","签证中没有该回单行",404)
    original=storage.get_receipt_by_sha(target["source_sha256"])
    report=verify_tokens(original["payload"],target,_secret())
    storage.audit(role,"reveal",{"receipt_no":receipt_no,"fields":list(report.keys()),
                                 "all_ok":report["all_ok"]},
                  visa_no=visa["visa_no"],receipt_no=receipt_no)
    return {"receipt_no":receipt_no,"masked_view":target,"source_sha256":target["source_sha256"],
            "verification":report,
            "original":original["payload"] if report["all_ok"] else None}
