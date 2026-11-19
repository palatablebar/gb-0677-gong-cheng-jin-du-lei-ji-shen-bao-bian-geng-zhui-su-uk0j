"""角色与权限矩阵（单机工作台，通过 X-Role 头声明，等同网关已认证身份）。

线上传输用 ASCII 键（clerk/general/finance/auditor），中文仅作显示标签，
因为 HTTP 头按 RFC 7230 只能承载 Latin-1 字符。
对外签证（脱敏展示/导出/摘要核验）：四种角色均可。
原始凭据回查：仅 财务、审计；总包与经办只看到脱敏值。
发布签证：仅 财务；经办、总包、审计均不可发布。
审计日志：仅 审计；其余角色不可见。
"""
from app.errors import DomainError

# ASCII 键 -> 中文显示标签
ROLE_LABELS={"clerk":"经办","general":"总包","finance":"财务","auditor":"审计"}
ROLES=tuple(ROLE_LABELS.values())
_ROLE_BY_LABEL={v:k for k,v in ROLE_LABELS.items()}
PERMISSIONS={
    # 能力          经办   总包   财务   审计
    "view_masked": (True, True, True, True),
    "export":      (True, True, True, True),
    "verify":      (True, True, True, True),
    "reveal":      (False, False, True, True),
    "publish":     (False, False, True, False),
    "audit_log":   (False, False, False, True),
}
def read_role(headers):
    """接受 ASCII 键；兼容直接传中文标签（仅测试/站内调用）。"""
    raw=headers.get("X-Role","clerk")
    if raw in ROLE_LABELS: return ROLE_LABELS[raw]
    if raw in _ROLE_BY_LABEL: return raw
    raise DomainError("BAD_ROLE",
                      f"角色需要是 {', '.join(ROLE_LABELS)}（X-Role 传 clerk/general/finance/auditor）",403)
def require(role,capability):
    if not PERMISSIONS[capability][ROLES.index(role)]:
        raise DomainError("FORBIDDEN",f"{role}无权执行该操作（需要{capability}权限）",403)
