import base64
import time
from gmssl import sm2

PUBKEY = "0491acf8c37019924eddbeec22867476532f21e3d252e6f2fc422af681dcaffd8052bacfe58e0477d293ae78aa5f7b62bb1feaa4cf55f56408e775e7011862b274"

def encrypt_pwd_for_login(password: str, public_key_hex: str = PUBKEY) -> dict:
    """
    返回：
      - pwd_plain: 加密前明文（password|timestamp_ms）
      - pwd_encrypted: 提交给后端的密文（hex, 04开头）
      - ts_ms: 毫秒时间戳
    """
    # 1) 业务层明文：密码|毫秒时间戳
    ts_ms = int(time.time() * 1000)
    pwd_plain = f"{password}|{ts_ms}"

    # 2) 对齐前端 sm2.js 预处理：UTF8 -> Base64 -> UTF8
    msg_bytes = base64.b64encode(pwd_plain.encode("utf-8"))  # bytes（ASCII）

    # 3) 公钥处理：如果带 04 前缀（130 hex），取最后 128 hex
    pub = public_key_hex.strip().lower()
    if len(pub) > 128:
        pub = pub[-128:]
    if len(pub) != 128:
        raise ValueError(f"公钥长度异常，处理后应为128 hex，当前={len(pub)}")

    # 4) SM2 加密（前端第三参=1，通常是 C1C3C2）
    try:
        crypt = sm2.CryptSM2(public_key=pub, private_key="", mode=1)
    except TypeError:
        # 某些 gmssl 版本没有 mode 参数
        crypt = sm2.CryptSM2(public_key=pub, private_key="")

    enc = crypt.encrypt(msg_bytes)

    # 5) 转 hex，并对齐前端外层固定补 04 前缀
    if isinstance(enc, bytes):
        cipher_hex = enc.hex().lower()
    else:
        cipher_hex = str(enc).strip().lower()

    if cipher_hex.startswith("04"):
        cipher_hex = cipher_hex[2:]
    pwd_encrypted = "04" + cipher_hex

    return {
        "pwd_plain": pwd_plain,
        "pwd_encrypted": pwd_encrypted,
        "ts_ms": ts_ms
    }


if __name__ == "__main__":
    result = encrypt_pwd_for_login("hircym-1vIhbi-bekmer")
    print("加密前明文:", result["pwd_plain"])
    print("提交用密码密文:", result["pwd_encrypted"])