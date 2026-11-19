"""回单与脱敏签证的 SQLite 存储。

原件与脱敏件分表存放；同一回单以 (receipt_no, source_sha256) 唯一约束，
重试导入同一文件不会新增记录。所有多步写操作在单事务内提交，失败整体回滚。
"""
import json,sqlite3
from datetime import datetime,timezone
from app.config import DATA_DIR
from app.errors import DomainError
from app.receipts.masking import sha256_hex,valid_id_card

RECEIPT_COLUMNS=["receipt_no","subcontractor","contact","id_card","phone",
                 "bank_account","item","period","amount","received_at"]

def connect():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    db_path=DATA_DIR/"receipts.db"
    db=sqlite3.connect(db_path,timeout=20)
    # 库存原件 PII，强制仅属主可读写
    if db_path.exists(): db_path.chmod(0o600)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""CREATE TABLE IF NOT EXISTS receipts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_no TEXT NOT NULL,
        source_file TEXT NOT NULL,
        source_sha256 TEXT NOT NULL,
        payload TEXT NOT NULL,
        UNIQUE(receipt_no,source_sha256))""")
    db.execute("""CREATE TABLE IF NOT EXISTS visas(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visa_no TEXT NOT NULL UNIQUE,
        period TEXT NOT NULL,
        version INTEGER NOT NULL,
        document_digest TEXT NOT NULL,
        input_sha256 TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        rows_json TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS visa_publications(
        visa_no TEXT PRIMARY KEY,
        active_visa_id INTEGER NOT NULL,
        version INTEGER NOT NULL,
        published_at TEXT NOT NULL,
        FOREIGN KEY(active_visa_id) REFERENCES visas(id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS visa_ledger(
        visa_no TEXT NOT NULL,
        source_sha256 TEXT NOT NULL,
        PRIMARY KEY(visa_no,source_sha256))""")
    db.execute("""CREATE TABLE IF NOT EXISTS visa_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visa_no TEXT NOT NULL,
        version INTEGER NOT NULL,
        result TEXT NOT NULL,
        reason TEXT,
        created_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        visa_no TEXT,
        receipt_no TEXT,
        detail TEXT NOT NULL)""")
    return db

def now_iso(): return datetime.now(timezone.utc).isoformat()

def audit(role,action,detail,visa_no=None,receipt_no=None):
    with connect() as db:
        db.execute("INSERT INTO audit_log(at,role,action,visa_no,receipt_no,detail) VALUES(?,?,?,?,?,?)",
                   (now_iso(),role,action,visa_no,receipt_no,json.dumps(detail,ensure_ascii=False)))

def validate_row(cells,header,line):
    row={"_line":line,"_raw":cells}
    if len(cells)!=len(header):
        return None,{"_line":line,"receipt_no":cells[0] if cells else "","reason":"BAD_COLUMNS","detail":"列数不匹配"}
    row.update(dict(zip(header,[c.strip() for c in cells])))
    if not row["receipt_no"]:
        return None,{"_line":line,"receipt_no":"","reason":"EMPTY_VALUE","detail":"回单号为空"}
    if not valid_id_card(row["id_card"]):
        return None,{"_line":line,"receipt_no":row["receipt_no"],"reason":"BAD_ID_CARD","detail":"身份证校验码不通过"}
    try:
        float(row["amount"])
    except ValueError:
        return None,{"_line":line,"receipt_no":row["receipt_no"],"reason":"INVALID_NUMBER","detail":"金额格式错误"}
    return row,None

def ingest(source_file,text):
    import csv,io,hashlib
    if not text or not text.strip(): raise DomainError("EMPTY_FILE","文件为空")
    stream=csv.reader(io.StringIO(text,newline=""))
    header=next(stream,None)
    if header!=RECEIPT_COLUMNS: raise DomainError("BAD_HEADER","回单表头不匹配，需要："+",".join(RECEIPT_COLUMNS))
    accepted,quarantine,seen_hashes=[],[],set()
    with connect() as db:
        for cells in stream:
            if not cells or not any(c.strip() for c in cells): continue
            line=stream.line_num
            row,bad=validate_row(cells,header,line)
            if bad: quarantine.append(bad);continue
            source_sha256=hashlib.sha256(json.dumps(row["_raw"],ensure_ascii=False).encode()).hexdigest()
            existing=db.execute("SELECT 1 FROM receipts WHERE receipt_no=? AND source_sha256=?",
                                (row["receipt_no"],source_sha256)).fetchone()
            if existing or source_sha256 in seen_hashes:
                quarantine.append({"_line":line,"receipt_no":row["receipt_no"],"reason":"DUPLICATE_SKIP","detail":"同一回单重试，未新增"})
                continue
            conflict=db.execute("SELECT 1 FROM receipts WHERE receipt_no=? AND source_sha256!=?",
                                (row["receipt_no"],source_sha256)).fetchone()
            if conflict:
                raise DomainError("RECEIPT_CONFLICT",f"回单 {row['receipt_no']} 已存在但内容不同，拒绝覆盖原件",409)
            payload={k:row[k] for k in RECEIPT_COLUMNS}
            db.execute("INSERT INTO receipts(receipt_no,source_file,source_sha256,payload) VALUES(?,?,?,?)",
                       (row["receipt_no"],source_file,source_sha256,json.dumps(payload,ensure_ascii=False)))
            accepted.append({**payload,"source_sha256":source_sha256})
            seen_hashes.add(source_sha256)
    return {"source_file":source_file,
            "metrics":{"inserted":len(accepted),"duplicates":sum(q["reason"]=="DUPLICATE_SKIP" for q in quarantine),
                       "quarantine":len(quarantine)},
            "rows":accepted,"quarantine":quarantine}

def list_receipts():
    with connect() as db:
        return [{"id":r["id"],"receipt_no":r["receipt_no"],"source_file":r["source_file"],
                 "source_sha256":r["source_sha256"],"payload":json.loads(r["payload"])}
                for r in db.execute("SELECT * FROM receipts ORDER BY id")]

def get_receipt_by_sha(source_sha256):
    with connect() as db:
        row=db.execute("SELECT * FROM receipts WHERE source_sha256=?",(source_sha256,)).fetchone()
    if not row: raise DomainError("NOT_FOUND","原始回单不存在",404)
    return {"id":row["id"],"receipt_no":row["receipt_no"],"source_file":row["source_file"],
            "source_sha256":row["source_sha256"],"payload":json.loads(row["payload"])}

def next_visa_no(period):
    with connect() as db:
        count=db.execute("SELECT COUNT(*) c FROM visas WHERE period=?",(period,)).fetchone()["c"]
    return f"QZ-{period.replace('-','')}-{count+1:03d}"

def active_publication():
    with connect() as db:
        pub=db.execute("SELECT * FROM visa_publications ORDER BY published_at DESC LIMIT 1").fetchone()
        if not pub: return None
        visa=db.execute("SELECT * FROM visas WHERE id=?",(pub["active_visa_id"],)).fetchone()
    return _visa_dict(visa)

def get_published(visa_no):
    with connect() as db:
        pub=db.execute("SELECT * FROM visa_publications WHERE visa_no=?",(visa_no,)).fetchone()
        if not pub: raise DomainError("NOT_FOUND","签证未发布或不存在",404)
        visa=db.execute("SELECT * FROM visas WHERE id=?",(pub["active_visa_id"],)).fetchone()
    return _visa_dict(visa)

def _visa_dict(row):
    return {"visa_no":row["visa_no"],"period":row["period"],"version":row["version"],
            "document_digest":row["document_digest"],"input_sha256":row["input_sha256"],
            "rule_version":row["rule_version"],"created_by":row["created_by"],
            "created_at":row["created_at"],"rows":json.loads(row["rows_json"])}

def list_versions(visa_no=None):
    sql="SELECT v.* FROM visas v";args=()
    if visa_no: sql+=" WHERE visa_no=?";args=(visa_no,)
    sql+=" ORDER BY v.id DESC"
    with connect() as db:
        rows=db.execute(sql,args).fetchall()
        pubs={r["visa_no"]:r["version"] for r in db.execute("SELECT visa_no,version FROM visa_publications")}
    return [{"visa_no":r["visa_no"],"period":r["period"],"version":r["version"],
             "document_digest":r["document_digest"],"created_by":r["created_by"],"created_at":r["created_at"],
             "active":pubs.get(r["visa_no"])==r["version"]} for r in rows]

def list_attempts():
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM visa_attempts ORDER BY id DESC")]

def audit_logs():
    with connect() as db:
        out=[]
        for r in db.execute("SELECT * FROM audit_log ORDER BY id DESC"):
            item=dict(r);item["detail"]=json.loads(item["detail"]);out.append(item)
        return out
