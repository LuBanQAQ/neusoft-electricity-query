import argparse
import json
import uuid
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import requests

from drjf_sign import decode_session_cookie, presign
from drjf_pwd import encrypt_pwd_for_login

HOST = "dldrxxxy.mp.sinojy.cn"
BASE = f"https://{HOST}"
SSO = "https://sso.mp.sinojy.cn"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="纯 requests 登录（SM2 加密密码）")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--service", default=BASE)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--session-file", default="session_dump.json")
    return p


def _normalize_referer(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return url
    return f"{BASE}/"


def build_redirect_uri(service: str) -> str:
    service_with_sso = f"{service}?ssoType=true"
    service_encoded = quote(service_with_sso, safe="")
    return f"https://{HOST}:443/api/user/ssoRedirect.do?service={service_encoded}"


def run_sso_login_flow(session: requests.Session, timeout: int, service: str) -> tuple[str, str]:
    session.post(
        f"{SSO}/oauth2.0/logout?service=",
        json={"service": service},
        headers={"content-type": "application/json;charset=UTF-8", "referer": f"{BASE}/", "user-agent": "Mozilla/5.0"},
        timeout=timeout,
    )

    redirect_raw = build_redirect_uri(service)
    redirect_param = quote(redirect_raw, safe="")
    rand = f"{uuid.uuid4().hex}"
    auth_pre = (
        f"{SSO}/oauth2.0/authorize?rand={rand}&response_type=code&client_id=111"
        f"&redirect_uri={redirect_param}&redirect_uri_domain={HOST}"
        "&loginByInterface=undefined&h5LoginUri=SL200000"
    )
    pre = session.get(auth_pre, allow_redirects=True, timeout=timeout)
    pre.raise_for_status()
    login_page_url = pre.url

    auth_post = (
        f"{SSO}/oauth2.0/authorize?redirect_uri={redirect_param}"
        f"&redirect_uri_domain={HOST}&h5LoginUri=SL200000"
    )
    return login_page_url, auth_post


def finalize_sso(session: requests.Session, login_page_url: str, auth_post_url: str, timeout: int) -> str:
    r = session.get(
        auth_post_url,
        headers={"referer": _normalize_referer(login_page_url), "user-agent": "Mozilla/5.0"},
        allow_redirects=True,
        timeout=timeout,
    )
    r.raise_for_status()
    return r.url


def fetch_user_base_info(session: requests.Session, timeout_seconds: int) -> dict:
    r = session.get(
        f"{BASE}/api/user/getUserBaseInfo",
        headers={"accept": "application/json, text/plain, */*", "referer": f"{BASE}/", "user-agent": "Mozilla/5.0"},
        timeout=timeout_seconds,
    )
    r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        return {}
    if isinstance(data, dict):
        return data
    return {}


def dump_session_file(
    session: requests.Session,
    session_file: str,
    final_url: str,
    login_data: dict,
    pwd_plain: str,
    site_info: dict,
    captured_sessiontoken: str,
) -> None:
    cookies_payload = []
    for c in session.cookies:
        expires = c.expires if c.expires is not None else -1
        cookies_payload.append(
            {
                "name": c.name,
                "value": c.value,
                "domain": c.domain or HOST,
                "path": c.path or "/",
                "expires": expires,
                "httpOnly": False,
                "secure": True,
                "sameSite": "Lax",
            }
        )

    data_json = login_data
    if not isinstance(data_json, dict):
        data_json = {}

    session_payload = {
        "url": final_url,
        "cookies": cookies_payload,
        "localStorage": {},
        "sessionStorage": {
            "loginData": json.dumps(data_json, ensure_ascii=False),
            "siteInfo": json.dumps(site_info, ensure_ascii=False),
        },
        "capturedSessionToken": captured_sessiontoken,
        "requestLogin": {"pwd_plain": pwd_plain},
    }
    Path(session_file).write_text(
        json.dumps(session_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def login_and_dump_session(
    username: str,
    password: str,
    timeout: int = 20,
    service: str = BASE,
    session_file: str = "session_dump.json",
) -> dict:
    def fetch_site_info(session: requests.Session, timeout_seconds: int, final_url: str, session_token: str) -> dict:
        final_parsed = urlparse(final_url)
        url_data = final_parsed.query or ""
        payload = {
            "domain": HOST,
            "isPayReturn": None,
            "merSwicthKeyArray": ["payment_others", "student_loan_remind"],
        }
        if url_data:
            payload["url_data"] = url_data
            q = parse_qs(url_data)
            if "ssoType" in q and q["ssoType"]:
                payload["ssoType"] = q["ssoType"][0]
        sign = presign(payload)
        headers = {
            "content-type": "application/json;charset=UTF-8",
            "accept": "application/json, text/plain, */*",
            "origin": BASE,
            "referer": final_url,
            "requestSiteDomain": HOST,
            "requestid": sign["requestid"],
            "rand": sign["rand"],
            "token": sign["token"],
            "sessionToken": session_token,
            "user-agent": "Mozilla/5.0",
        }
        r = session.post(
            f"{BASE}/api/pageService/firstInterFace",
            headers=headers,
            json=payload,
            timeout=timeout_seconds,
        )
        r.raise_for_status()
        try:
            site_info = r.json()
        except Exception:
            return {}
        if isinstance(site_info, dict):
            return site_info
        return {}

    with requests.Session() as s:
        login_page_url, auth_post_url = run_sso_login_flow(s, timeout, service)
        result, plain = post_login(
            session=s,
            username=username,
            password=password,
            service=service,
            referer=login_page_url,
            timeout=timeout,
        )

        code = str(result.get("code", ""))
        typ = str(result.get("type", ""))
        success = typ == "S" or code in {"00000000", "0", "200"}
        if not success:
            return {
                "success": False,
                "loginResult": result,
                "message": result.get("message") or result.get("msg") or "登录失败",
            }

        final_url = finalize_sso(s, login_page_url, auth_post_url, timeout)

        user_base = fetch_user_base_info(s, timeout)
        user_base_data = user_base.get("data_json") if isinstance(user_base, dict) else {}
        if not isinstance(user_base_data, dict):
            user_base_data = {}

        session_cookie_value = s.cookies.get("SESSION", domain=HOST) or s.cookies.get("SESSION") or ""
        decoded_session = decode_session_cookie(session_cookie_value)
        session_token = (
            user_base_data.get("sessionToken")
            or result.get("data_json", {}).get("sessionToken")
            or decoded_session
            or ""
        )

        site_info = fetch_site_info(s, timeout, final_url, session_token)
        if not site_info:
            site_info = {
                "is_login": True,
                "current_merchant_id": 113377,
                "sessionToken": session_token,
            }
        elif not site_info.get("sessionToken"):
            site_info["sessionToken"] = session_token

        dump_session_file(
            s,
            session_file,
            final_url,
            user_base_data,
            plain,
            site_info,
            session_token,
        )
        return {
            "success": True,
            "loginResult": result,
            "userBaseCode": user_base.get("code") if isinstance(user_base, dict) else None,
            "siteInfoCode": site_info.get("code") if isinstance(site_info, dict) else None,
            "sessionToken": session_token,
            "finalUrl": final_url,
            "cookies": s.cookies.get_dict(),
            "sessionFile": str(Path(session_file).resolve()),
        }


def post_login(session: requests.Session, username: str, password: str, service: str, referer: str, timeout: int) -> tuple[dict, str]:
    enc = encrypt_pwd_for_login(password)
    payload = {
        "userName": username,
        "pwd": enc["pwd_encrypted"],
        "service": service,
    }
    headers = {
        "content-type": "application/json;charset=UTF-8",
        "accept": "application/json, text/plain, */*",
        "origin": BASE,
        "referer": _normalize_referer(referer),
        "user-agent": "Mozilla/5.0",
    }
    r = session.post(f"{SSO}/oauth2.0/loginSubmit", json=payload, headers=headers, timeout=timeout)
    r.raise_for_status()
    try:
        return r.json(), enc["pwd_plain"]
    except Exception:
        return {"raw": r.text}, enc["pwd_plain"]


def main() -> int:
    args = build_parser().parse_args()
    out = login_and_dump_session(
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        service=args.service,
        session_file=args.session_file,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
