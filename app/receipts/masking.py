"""个人信息脱敏与可核验绑定。

原则：只产出新的脱敏对象，绝不改写原始回单；原值不出现在任何对外字段中。
- 展示值（masked）：对外可见，规则固定、结果确定。
- 令牌（token）：HMAC-SHA256(原件值, 服务端密钥) 的截断摘要，不含原值，
  持密钥角色可对原件重新计算并比对，外部角色无法反推。
- 行摘要（line_digest）：对脱敏后整行规范化求 SHA256，任何拿到签证的人
  都可重算，用于发现篡改。
"""
import hashlib,hmac,json
from app.errors import DomainError

PII_FIELDS=("contact","id_card","phone","bank_account")
ID_WEIGHTS=(7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2)
ID_CHECK_CODES="10X98765432"

def canonical(obj):
    return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode()

def sha256_hex(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def valid_id_card(value):
    """GB 11643 十八位身份证校验码核验。"""
    text=str(value).strip().upper()
    if len(text)!=18 or not text[:17].isdigit() or not (text[17].isdigit() or text[17]=="X"):
        return False
    total=sum(int(d)*w for d,w in zip(text[:17],ID_WEIGHTS))
    return ID_CHECK_CODES[total%11]==text[17]

def mask_id_card(value):
    text=str(value).strip()
    if len(text)!=18: raise DomainError("BAD_ID_CARD","身份证号应为18位")
    return text[:6]+"*"*8+text[-4:]

def mask_name(value):
    text=str(value).strip()
    if not text: raise DomainError("EMPTY_VALUE","联系人不能为空")
    return text[0]+("*"*(len(text)-1) if len(text)>1 else "*")

def mask_phone(value):
    text=str(value).strip()
    if len(text)<7: raise DomainError("BAD_PHONE","联系电话长度不足")
    return text[:3]+"*"*(len(text)-7)+text[-4:]

def mask_bank(value):
    text=str(value).strip()
    if len(text)<4: raise DomainError("BAD_BANK","银行账号长度不足")
    return "*"*(len(text)-4)+text[-4:]

MASKERS={"id_card":mask_id_card,"contact":mask_name,"phone":mask_phone,"bank_account":mask_bank}

def hmac_token(secret,field,value):
    mac=hmac.new(secret,f"{field}\x00{value}".encode(),hashlib.sha256)
    return mac.hexdigest()[:16]

def mask_field(field,value,secret):
    masked=MASKERS[field](value)
    return {"masked":masked,"token":hmac_token(secret,field,value)}

def mask_receipt(original,secret):
    """原始回单行 -> 对外签证行（副本，不修改入参）。"""
    masked=dict(original)
    masked.pop("_line",None);masked.pop("_raw",None)
    pii={}
    for field in PII_FIELDS:
        if field not in masked: continue
        item=mask_field(field,str(masked[field]),secret)
        pii[field]=item
        masked[field]=item["masked"]
    masked["_pii"]={f:v["token"] for f,v in pii.items()}
    line_digest=sha256_hex({k:v for k,v in masked.items() if k!="line_digest"})
    masked["line_digest"]=line_digest
    return masked

def recompute_line_digest(masked_row):
    return sha256_hex({k:v for k,v in masked_row.items() if k!="line_digest"})

def verify_tokens(original,masked_row,secret):
    """持密钥角色：逐字段比对 HMAC 令牌，返回核验明细。"""
    report={}
    ok=True
    for field in PII_FIELDS:
        if field not in masked_row.get("_pii",{}): continue
        expected=hmac_token(secret,field,str(original[field]))
        passed=hmac.compare_digest(expected,masked_row["_pii"][field])
        report[field]={"token_ok":passed,"masked":masked_row[field]}
        ok=ok and passed
    report["line_digest_ok"]=recompute_line_digest(masked_row)==masked_row.get("line_digest")
    report["all_ok"]=ok and report["line_digest_ok"]
    return report
