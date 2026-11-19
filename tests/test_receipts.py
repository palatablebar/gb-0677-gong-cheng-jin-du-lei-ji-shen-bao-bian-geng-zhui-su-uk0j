import csv,io,json
import pytest
from app import store as claim_store
from app.config import ROOT
from app.receipts import storage,service
from app.receipts.masking import mask_receipt,valid_id_card,mask_name,mask_id_card
from app.receipts.secret import load_secret

RECEIPTS_DIR=ROOT/"sample_data"/"receipts"

@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    monkeypatch.setattr(claim_store,"DATA_DIR",tmp_path)
    monkeypatch.setattr(storage,"DATA_DIR",tmp_path)
    monkeypatch.delenv("RECEIPT_HMAC_SECRET",raising=False)
    yield

@pytest.fixture
def client():
    from app.main import create_app
    return create_app().test_client()

def _read(name): return (RECEIPTS_DIR/name).read_text(encoding="utf-8")

def _ingest(client,path,role="clerk"):
    from werkzeug.datastructures import FileStorage
    fs=FileStorage(stream=open(RECEIPTS_DIR/path,"rb"),filename=path)
    return client.post("/api/receipts/ingest",data={"file":fs},
                       headers={"X-Role":role},content_type="multipart/form-data")

# ---------- 脱敏规则 ----------
def test_id_checksum_rule():
    assert valid_id_card("110101198503120017")
    assert not valid_id_card("110101198503120010")

def test_mask_keeps_edges_only():
    assert mask_id_card("110101198503120017")=="110101********0017"
    assert mask_name("张伟")=="张*"
    assert mask_name("欧阳修")=="欧**"

def test_masked_row_has_no_original_pii():
    secret=b"0"*32
    original={"receipt_no":"X1","contact":"张伟","id_card":"110101198503120017",
              "phone":"13800010001","bank_account":"6222021234567890001","amount":"100.00"}
    masked=mask_receipt(original,secret)
    blob=json.dumps(masked,ensure_ascii=False)
    for leak in ("张伟","110101198503120017","13800010001","6222021234567890001"):
        assert leak not in blob
    # 原件不被修改
    assert original["contact"]=="张伟" and original["id_card"]=="110101198503120017"

def test_token_deterministic_and_bound_to_field():
    secret=b"0"*32
    a=mask_receipt({"id_card":"110101198503120017","contact":"张伟"},secret)
    b=mask_receipt({"id_card":"110101198503120017","contact":"张伟"},secret)
    assert a["_pii"]==b["_pii"]
    other=mask_receipt({"id_card":"110101198503120017","contact":"李娜"},secret)
    assert other["_pii"]["contact"]!=a["_pii"]["contact"]
    assert other["_pii"]["id_card"]==a["_pii"]["id_card"]

# ---------- 导入与重试幂等 ----------
def test_ingest_then_retry_inserts_nothing_new(client):
    r1=_ingest(client,"receipts-nov.csv");assert r1.status_code==200
    assert r1.get_json()["metrics"]["inserted"]==6
    r2=_ingest(client,"receipts-nov.csv")
    m=r2.get_json()["metrics"]
    assert m["inserted"]==0 and m["duplicates"]==6
    assert len(storage.list_receipts())==6

def test_retry_file_with_bad_checksum_quarantined_not_inserted(client):
    _ingest(client,"receipts-nov.csv")
    r=_ingest(client,"receipts-retry.csv")
    body=r.get_json()
    assert body["metrics"]["inserted"]==0 and body["metrics"]["duplicates"]==3
    reasons={q["reason"] for q in body["quarantine"]}
    assert "BAD_ID_CARD" in reasons and "DUPLICATE_SKIP" in reasons
    # 坏数据没有进入原件库
    assert all(x["receipt_no"]!="FB2026110007" for x in storage.list_receipts())

def test_same_receipt_no_different_content_rejected_409(client):
    from werkzeug.datastructures import FileStorage
    _ingest(client,"receipts-nov.csv")
    text=_read("receipts-nov.csv").replace("186500.00","186500.99")
    r=client.post("/api/receipts/ingest",
                  data={"file":FileStorage(stream=io.BytesIO(text.encode()),filename="tampered.csv")},
                  content_type="multipart/form-data")
    assert r.status_code==409 and r.get_json()["code"]=="RECEIPT_CONFLICT"
    # 原件金额未被覆盖
    assert storage.list_receipts()[0]["payload"]["amount"]=="186500.00"

# ---------- 发布：失败保留旧版 ----------
def test_publish_failure_keeps_old_version(client):
    _ingest(client,"receipts-nov.csv")
    ok=client.post("/api/receipts/visa/publish",json={"period":"2026-11"},
                   headers={"X-Role":"finance"}).get_json()
    assert ok["action"]=="created" and ok["visa"]["version"]==1
    before=storage.active_publication()
    # 即使同一批回单重试，故障注入先生效；失败后旧版仍为当前发布
    r=client.post("/api/receipts/visa/publish",json={"period":"2026-11","simulate_failure":True},
                  headers={"X-Role":"finance"})
    assert r.status_code==500 and r.get_json()["code"]=="PUBLISH_FAILED"
    after=storage.active_publication()
    assert after["visa_no"]==before["visa_no"] and after["document_digest"]==before["document_digest"]
    # 失败留痕，但没有产生新版本签证
    assert all(v["version"]==1 for v in storage.list_versions())
    assert storage.list_attempts()[0]["result"]=="failed"
    # 失败后再正常重试，命中台账幂等，仍指向同一签证
    again=client.post("/api/receipts/visa/publish",json={"period":"2026-11"},
                      headers={"X-Role":"finance"}).get_json()
    assert again["action"]=="reused" and again["visa"]["visa_no"]==before["visa_no"]

def test_retry_publish_same_receipts_returns_reused_no_new_visa(client):
    _ingest(client,"receipts-nov.csv")
    first=client.post("/api/receipts/visa/publish",json={"period":"2026-11"},
                      headers={"X-Role":"finance"}).get_json()
    again=client.post("/api/receipts/visa/publish",json={"period":"2026-11"},
                      headers={"X-Role":"finance"}).get_json()
    assert again["action"]=="reused"
    assert again["visa"]["visa_no"]==first["visa"]["visa_no"]
    assert len(storage.list_versions())==1

# ---------- 角色权限 ----------
def test_role_matrix_for_publish_and_reveal(client):
    _ingest(client,"receipts-nov.csv")
    client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":"finance"})
    visa=storage.active_publication();no=visa["visa_no"];rn=visa["rows"][0]["receipt_no"]
    for role in ("clerk","general","auditor"):
        r=client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":role})
        assert r.status_code==403
    for role in ("clerk","general"):
        r=client.get(f"/api/receipts/visa/{no}/reveal/{rn}",headers={"X-Role":role})
        assert r.status_code==403
    for role in ("finance","auditor"):
        r=client.get(f"/api/receipts/visa/{no}/reveal/{rn}",headers={"X-Role":role})
        assert r.status_code==200 and r.get_json()["verification"]["all_ok"]

def test_chinese_role_label_backward_compatible(client):
    # 站内/测试直接传中文标签仍可识别（线上 HTTP 头用 ASCII 键）
    _ingest(client,"receipts-nov.csv")
    client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":"财务"})
    no=storage.active_publication()["visa_no"];rn=storage.active_publication()["rows"][0]["receipt_no"]
    assert client.get(f"/api/receipts/visa/{no}/reveal/{rn}",headers={"X-Role":"审计"}).status_code==200
    assert client.get("/api/receipts/visa/active",headers={"X-Role":"总包"}).status_code==200

def test_audit_log_auditor_only(client):
    _ingest(client,"receipts-nov.csv")
    client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":"finance"})
    assert client.get("/api/receipts/audit-log",headers={"X-Role":"finance"}).status_code==403
    logs=client.get("/api/receipts/audit-log",headers={"X-Role":"auditor"}).get_json()["entries"]
    assert any(e["action"]=="publish" for e in logs)

def test_bad_role_rejected(client):
    r=client.get("/api/receipts",headers={"X-Role":"outsider"})
    assert r.status_code==403 and r.get_json()["code"]=="BAD_ROLE"
    r2=client.get("/api/receipts",headers={"X-Role":"外包"})
    assert r2.status_code==403 and r2.get_json()["code"]=="BAD_ROLE"

# ---------- 可核验 ----------
def test_public_verify_detects_tampering(client):
    _ingest(client,"receipts-nov.csv")
    client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":"finance"})
    no=storage.active_publication()["visa_no"]
    ok=client.get(f"/api/receipts/visa/{no}/verify",headers={"X-Role":"general"}).get_json()
    assert ok["lines_ok"] and ok["document_digest_ok"]
    # 篡改对外数据后摘要核验失败（模拟中间人改数）
    visa=storage.get_published(no)
    visa["rows"][0]["amount"]="999999.99"
    report=service.verify(visa)
    assert not report["lines_ok"]

def test_reveal_binds_masked_row_back_to_original(client):
    _ingest(client,"receipts-nov.csv")
    client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":"finance"})
    visa=storage.active_publication();no=visa["visa_no"];rn=visa["rows"][0]["receipt_no"]
    body=client.get(f"/api/receipts/visa/{no}/reveal/{rn}",headers={"X-Role":"auditor"}).get_json()
    assert body["verification"]["all_ok"]
    assert body["original"]["receipt_no"]==rn
    assert body["masked_view"]["id_card"]!=body["original"]["id_card"]
    # 回查动作进入审计日志
    logs=storage.audit_logs()
    assert any(e["action"]=="reveal" and e["receipt_no"]==rn for e in logs)

def test_export_csv_is_masked(client):
    _ingest(client,"receipts-nov.csv")
    client.post("/api/receipts/visa/publish",json={"period":"2026-11"},headers={"X-Role":"finance"})
    no=storage.active_publication()["visa_no"]
    r=client.get(f"/api/receipts/visa/{no}/export",headers={"X-Role":"general"})
    assert r.status_code==200
    text=r.data.decode("utf-8-sig")
    assert "110101********0017" in text
    assert "110101198503120017" not in text and "张伟" not in text
    rows=list(csv.reader(io.StringIO(text)))
    assert len(rows)==7 and "document_digest" in rows[0]

def test_secret_file_is_owner_only(tmp_path):
    key=load_secret(tmp_path)
    path=tmp_path/"receipt_hmac.key"
    assert path.stat().st_mode&0o077==0 and len(key)>=32

def test_receipt_db_is_owner_only(client,tmp_path):
    _ingest(client,"receipts-nov.csv")
    db_file=tmp_path/"receipts.db"
    assert db_file.stat().st_mode&0o077==0

def test_page_renders(client):
    assert client.get("/receipts").status_code==200
