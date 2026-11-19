"""HMAC 主密钥管理。

优先级：环境变量 RECEIPT_HMAC_SECRET > 数据目录下 0600 权限的本地密钥文件。
生产环境应改用 KMS/密钥服务注入；本地文件仅用于单机工作台。
密钥只用于内部核验，永不写入对外签证。
"""
import os,secrets
from pathlib import Path
_CACHE={}
def load_secret(data_dir):
    data_dir=Path(data_dir)
    env=os.environ.get("RECEIPT_HMAC_SECRET")
    if env:
        if len(env)<16: raise RuntimeError("RECEIPT_HMAC_SECRET 至少16字符")
        return env.encode()
    if str(data_dir) in _CACHE: return _CACHE[str(data_dir)]
    path=data_dir/"receipt_hmac.key"
    if not path.exists():
        data_dir.mkdir(parents=True,exist_ok=True)
        path.write_bytes(secrets.token_bytes(32).hex().encode())
        path.chmod(0o600)
    if path.stat().st_mode&0o077: path.chmod(0o600)
    key=path.read_bytes().strip()
    _CACHE[str(data_dir)]=key
    return key
