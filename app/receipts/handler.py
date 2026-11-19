"""回单脱敏签证 HTTP 接口。

角色通过 X-Role 头声明（默认经办）；对外接口只返回脱敏数据，
原件回查走 /reveal 且受权限控制并写审计日志。
"""
import csv,io
from flask import Blueprint,request,jsonify,current_app
from app.errors import DomainError
from app.receipts import storage,service,roles
bp=Blueprint("receipts",__name__)

@bp.post("/api/receipts/ingest")
def ingest():
    file=request.files.get("file")
    if not file: raise DomainError("NO_FILE","请选择回单CSV文件")
    raw=file.read()
    for enc in ("utf-8-sig","gb18030"):
        try: text=raw.decode(enc);break
        except UnicodeDecodeError: continue
    else: raise DomainError("ENCODING","无法识别文件编码")
    result=storage.ingest(file.filename,text)
    return jsonify(result)

@bp.get("/api/receipts")
def receipts_list():
    role=roles.read_role(request.headers)
    roles.require(role,"view_masked")
    # 列表也不回传 PII 原值，仅回编号、分包、摘要
    return jsonify({"role":role,"receipts":[
        {"receipt_no":r["receipt_no"],"subcontractor":r["payload"]["subcontractor"],
         "period":r["payload"]["period"],"amount":r["payload"]["amount"],
         "source_file":r["source_file"],"source_sha256":r["source_sha256"]}
        for r in storage.list_receipts()]})

@bp.post("/api/receipts/visa/build")
def build_visa():
    role=roles.read_role(request.headers)
    p=request.get_json(silent=True) or {}
    period=p.get("period")
    if not isinstance(period,str) or not period: raise DomainError("BAD_PERIOD","请提供签证周期，如 2026-11")
    return jsonify(service.build(period,role))

@bp.post("/api/receipts/visa/publish")
def publish_visa():
    role=roles.read_role(request.headers)
    roles.require(role,"publish")
    p=request.get_json(silent=True) or {}
    period=p.get("period")
    if not isinstance(period,str) or not period: raise DomainError("BAD_PERIOD","请提供签证周期，如 2026-11")
    visa,action=service.publish(period,role,fail_after_write=bool(p.get("simulate_failure")))
    return jsonify({"action":action,"visa":visa})

@bp.get("/api/receipts/visa/active")
def active_visa():
    role=roles.read_role(request.headers)
    roles.require(role,"view_masked")
    visa=storage.active_publication()
    if not visa: return jsonify({"role":role,"visa":None})
    return jsonify({"role":role,"visa":visa})

@bp.get("/api/receipts/visa/<visa_no>")
def visa_detail(visa_no):
    role=roles.read_role(request.headers)
    roles.require(role,"view_masked")
    return jsonify({"role":role,"visa":storage.get_published(visa_no)})

@bp.get("/api/receipts/visa/<visa_no>/verify")
def verify_visa(visa_no):
    role=roles.read_role(request.headers)
    roles.require(role,"verify")
    return jsonify({"role":role,**service.verify(storage.get_published(visa_no))})

@bp.get("/api/receipts/visa/<visa_no>/reveal/<receipt_no>")
def reveal(visa_no,receipt_no):
    role=roles.read_role(request.headers)
    roles.require(role,"reveal")
    return jsonify({"role":role,**service.traceback(storage.get_published(visa_no),receipt_no,role)})

@bp.get("/api/receipts/visa/<visa_no>/export")
def export_visa(visa_no):
    role=roles.read_role(request.headers)
    roles.require(role,"export")
    visa=storage.get_published(visa_no)
    stream=io.StringIO(newline="");w=csv.writer(stream)
    w.writerow(["visa_no","version","period","rule_version","document_digest","receipt_no",
                "subcontractor","contact_masked","id_card_masked","phone_masked","bank_account_masked",
                "item","amount","source_sha256","line_digest"])
    for r in visa["rows"]:
        w.writerow([visa["visa_no"],visa["version"],visa["period"],visa["rule_version"],
                    visa["document_digest"],r["receipt_no"],r["subcontractor"],r["contact"],
                    r["id_card"],r["phone"],r["bank_account"],r["item"],r["amount"],
                    r["source_sha256"],r["line_digest"]])
    storage.audit(role,"export",{"visa_no":visa_no,"rows":len(visa["rows"])},visa_no=visa_no)
    return current_app.response_class(
        ("﻿"+stream.getvalue()).encode("utf-8"),mimetype="text/csv",
        headers={"Content-Disposition":f'attachment; filename="visa-{visa_no}-masked.csv"'})

@bp.get("/api/receipts/visa/versions")
def versions():
    role=roles.read_role(request.headers)
    roles.require(role,"view_masked")
    visa_no=request.args.get("visa_no")
    return jsonify({"role":role,"versions":storage.list_versions(visa_no),"attempts":storage.list_attempts()})

@bp.get("/api/receipts/audit-log")
def audit_log():
    role=roles.read_role(request.headers)
    roles.require(role,"audit_log")
    return jsonify({"role":role,"entries":storage.audit_logs()})

@bp.get("/receipts")
def page():
    from flask import render_template
    return render_template("receipts.html")
