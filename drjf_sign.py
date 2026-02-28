import argparse
import base64
import hashlib
import json
import random
import time
from pathlib import Path

import requests


HOST = "dldrxxxy.mp.sinojy.cn"
BASE_URL = f"https://{HOST}"
API_PATH = "/api/rechargeMobileService/selectAndCheckOrder"


def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def gen_reqid() -> str:
    ts = str(int(time.time() * 1000))
    rand_suffix = str(random.random())[2:7]
    return "403" + ts[-5:] + rand_suffix


def gen_rand(length: int) -> str:
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length))


def gen_token(payload: dict, rand: str) -> str:
    payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    h1 = md5(payload_str)
    h2 = md5(str(rand)[-6:] + h1)
    return md5("hgf434h767s3r56f" + h2)


def presign(payload: dict) -> dict:
    rand = gen_rand(13)
    return {
        "requestid": gen_reqid(),
        "rand": rand,
        "token": gen_token(payload, rand),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="复用 session_dump.json 自动调电费查询接口（只传寝室号）")
    parser.add_argument("custRechNo", nargs="?", help="寝室号，如 7-A608")
    parser.add_argument("--session-file", default="session_dump.json", help="Playwright 导出的会话文件")
    parser.add_argument("--merchantId", type=int, default=None)
    parser.add_argument("--userInfoId", type=int, default=None)
    parser.add_argument("--rechMerMapId", type=int, default=326)
    parser.add_argument("--custRechNo", dest="custRechNoOpt", default=None, help="寝室号，如 7-A608")
    parser.add_argument(
        "--sessiontoken",
        default="",
        help="请求头 sessiontoken（抓包里看到的 UUID），可留空",
    )
    parser.add_argument("--timeout", type=int, default=20, help="请求超时时间（秒）")
    return parser


def load_session_cookies(session: requests.Session, session_file: str) -> str | None:
    path = Path(session_file)
    payload = json.loads(path.read_text(encoding="utf-8"))
    cookies = payload.get("cookies", [])

    session_cookie = None
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        domain = cookie.get("domain") or HOST
        if not name or value is None:
            continue
        session.cookies.set(name, value, domain=domain, path=cookie.get("path", "/"))
        if name.upper() == "SESSION" and HOST in domain:
            session_cookie = value
    return session_cookie


def parse_json_or_empty(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def decode_session_cookie(session_cookie: str | None) -> str:
    if not session_cookie:
        return ""
    try:
        padded = session_cookie + "=" * (-len(session_cookie) % 4)
        decoded = base64.b64decode(padded).decode("utf-8").strip()
        return decoded
    except Exception:
        return ""


def extract_defaults_from_session(session_file: str) -> dict:
    path = Path(session_file)
    payload = json.loads(path.read_text(encoding="utf-8"))
    session_storage = payload.get("sessionStorage", {})
    captured_sessiontoken = payload.get("capturedSessionToken")

    login_data = parse_json_or_empty(session_storage.get("loginData"))
    site_info = parse_json_or_empty(session_storage.get("siteInfo"))

    session_cookie = None
    for cookie in payload.get("cookies", []):
        if cookie.get("name", "").upper() == "SESSION" and HOST in (cookie.get("domain") or ""):
            session_cookie = cookie.get("value")
            break

    sessiontoken = captured_sessiontoken or site_info.get("sessionToken") or decode_session_cookie(session_cookie)

    return {
        "userInfoId": login_data.get("userInfoId"),
        "merchantId": site_info.get("current_merchant_id") or 113377,
        "sessiontoken": sessiontoken,
    }


def query_electricity(
    session: requests.Session,
    merchant_id: int,
    user_info_id: int,
    rech_mer_map_id: int,
    cust_rech_no: str,
    sessiontoken: str,
    timeout: int,
) -> dict:
    body = {
        "merchantId": merchant_id,
        "userInfoId": user_info_id,
        "rechMerMapId": rech_mer_map_id,
        "custRechNo": cust_rech_no,
    }
    sign = presign(body)

    headers = {
        "content-type": "application/json;charset=UTF-8",
        "accept": "*/*",
        "origin": BASE_URL,
        "referer": f"{BASE_URL}/",
        "requestsitedomain": HOST,
        "requestid": sign["requestid"],
        "rand": sign["rand"],
        "token": sign["token"],
        "sessiontoken": sessiontoken,
        "user-agent": "Mozilla/5.0",
    }

    resp = session.post(
        f"{BASE_URL}{API_PATH}",
        headers=headers,
        json=body,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    args = build_parser().parse_args()
    cust_rech_no = args.custRechNoOpt or args.custRechNo
    if not cust_rech_no:
        raise SystemExit("[ERROR] 请传寝室号：例如 drjf_sign.py 7-A608")

    defaults = extract_defaults_from_session(args.session_file)
    resolved_user_info_id = args.userInfoId or defaults.get("userInfoId")
    resolved_merchant_id = args.merchantId or defaults.get("merchantId") or 113377
    resolved_sessiontoken = args.sessiontoken or defaults.get("sessiontoken") or ""

    if not resolved_user_info_id:
        raise SystemExit("[ERROR] 无法自动获取 userInfoId，请先执行 login_requests.py 或 drjf_auto.py 生成 session_dump.json")

    with requests.Session() as session:
        session_cookie = load_session_cookies(session, args.session_file)
        if session_cookie:
            print(f"[INFO] SESSION={session_cookie}")
        else:
            print("[WARN] session_dump.json 中未找到 dldrxxxy.mp.sinojy.cn 域下的 SESSION")
        print(
            f"[INFO] params: merchantId={resolved_merchant_id}, userInfoId={resolved_user_info_id}, rechMerMapId={args.rechMerMapId}, custRechNo={cust_rech_no}"
        )
        print(f"[INFO] sessiontoken={'(empty)' if not resolved_sessiontoken else resolved_sessiontoken}")

        result = query_electricity(
            session=session,
            merchant_id=resolved_merchant_id,
            user_info_id=resolved_user_info_id,
            rech_mer_map_id=args.rechMerMapId,
            cust_rech_no=cust_rech_no,
            sessiontoken=resolved_sessiontoken,
            timeout=args.timeout,
        )

        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())