#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cron: 15 8,20 * * *
new Env("东软电费查询");

青龙环境变量（推荐）：
1) 多账号（优先）
   DRJF_ACCOUNTS=用户名,密码,寝室号[,备注]\n用户名2,密码2,寝室号2[,备注]
   - 也支持用 & 分隔多账号；单账号字段也支持 @ 或 # 分隔（会自动识别）

2) 单账号（兼容）
   DRJF_USERNAME=xxx
   DRJF_PASSWORD=xxx
   DRJF_CUST_RECH_NO=7-A608

可选变量：
- DRJF_CONFIG=配置文件路径（JSON，可选，仍通过环境变量指定）
- DRJF_SESSION_DIR=会话目录（默认 ./drjf_sessions）
- DRJF_SESSION_FILE=单账号模式指定会话文件（可选）
- DRJF_TIMEOUT=接口超时秒数（默认20）
- DRJF_LOGIN_TIMEOUT=登录超时秒数（默认20）
- DRJF_RECH_MER_MAP_ID=默认326
- DRJF_MERCHANT_ID=默认113377（也可自动从会话提取）
- DRJF_USER_INFO_ID=可手动指定（通常无需）
- DRJF_SESSIONTOKEN=可手动指定（通常无需）
- DRJF_NOTIFY=1/0 是否发送通知（默认1）
- DRJF_NOTIFY_ONLY_FAIL=1 仅失败时通知（默认0）
- DRJF_LOW_THRESHOLD=低电量阈值（数字，可选；低于则标记⚠️）
- DRJF_NOTIFY_ON_CHANGE=1 仅数据变更/低阈值/周统计时通知（默认1）
- DRJF_WEEKLY_STATS=1 开启每周用电统计（默认1）
- DRJF_WEEKLY_NOTIFY_WEEKDAY=0 每周统计通知日（0=周一..6=周日，默认0）
- DRJF_STATE_DIR=状态与历史目录（默认 ./drjf_state）
- DRJF_DEBUG=1 输出调试日志
- DRJF_RAW=1 控制台打印成功项完整原始 JSON（默认0）

依赖：requests, gmssl
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import traceback
import uuid
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

import requests
Session = requests.Session  # type: ignore[attr-defined]

try:
    from gmssl import sm2
except Exception as _gmssl_err:  # 延后报错，方便展示更友好的提示
    sm2 = None  # type: ignore
    _GMSSL_IMPORT_ERROR = _gmssl_err
else:
    _GMSSL_IMPORT_ERROR = None


HOST = "dldrxxxy.mp.sinojy.cn"
BASE = f"https://{HOST}"
SSO = "https://sso.mp.sinojy.cn"
API_SELECT_AND_CHECK_ORDER = f"{BASE}/api/rechargeMobileService/selectAndCheckOrder"
API_GET_USER_BASE = f"{BASE}/api/user/getUserBaseInfo"
API_FIRST_INTERFACE = f"{BASE}/api/pageService/firstInterFace"
PUBKEY = "0491acf8c37019924eddbeec22867476532f21e3d252e6f2fc422af681dcaffd8052bacfe58e0477d293ae78aa5f7b62bb1feaa4cf55f56408e775e7011862b274"
UA = "Mozilla/5.0"
DEFAULT_MERCHANT_ID = 113377
DEFAULT_RECH_MER_MAP_ID = 326


# =========================
# 通用工具
# =========================

def dprint(*args: Any) -> None:
    if str(os.getenv("DRJF_DEBUG", "0")).strip() in {"1", "true", "True", "yes", "on"}:
        print("[DEBUG]", *args)


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


def parse_json_or_empty(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def decode_session_cookie(session_cookie: Optional[str]) -> str:
    if not session_cookie:
        return ""
    try:
        padded = session_cookie + "=" * (-len(session_cookie) % 4)
        return base64.b64decode(padded).decode("utf-8").strip()
    except Exception:
        return ""


def looks_like_success(result: dict) -> bool:
    """严格成功判定（登录/用户信息类接口）：仅接受 code == "00000000"。"""
    if not isinstance(result, dict):
        return False
    return str(result.get("code", "")).strip() == "00000000"


def looks_like_query_success(result: dict) -> bool:
    """严格成功判定（电费查询接口）：仅接受 type == "S" 且 code == "30300000"。"""
    if not isinstance(result, dict):
        return False
    code = str(result.get("code", "")).strip()
    typ = str(result.get("type", "")).strip()
    return typ == "S" and code == "30300000"


def looks_like_auth_expired(result: dict) -> bool:
    code = str(result.get("code", "")).strip()
    text_parts = [
        code,
        str(result.get("message", "")),
        str(result.get("msg", "")),
        str(result.get("error", "")),
        str(result.get("detail", "")),
    ]
    text = " ".join(text_parts).lower()

    if code in {"401", "40001", "40101", "1001", "9001"}:
        return True

    keywords = ["未登录", "登录", "过期", "失效", "超时", "session", "token", "auth", "认证"]
    return any(k in text for k in keywords)


def safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if not s:
        return None
    # 提取第一个数字（支持负数/小数）
    m = re.search(r"-?\d+(?:\.\d+)?", s)
    if not m:
        return None
    try:
        return float(m.group(0))
    except Exception:
        return None


def fmt_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def ensure_int(value: Any, name: str) -> int:
    if value is None or str(value).strip() == "":
        raise ValueError(f"参数 {name} 不能为空")
    return int(str(value).strip())


def parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "y"}


def parse_int_env(name: str, default: Optional[int] = None) -> Optional[int]:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(str(raw).strip())
    except Exception:
        return default


def _json_deepcopy(x: Any) -> Any:
    try:
        return json.loads(json.dumps(x, ensure_ascii=False))
    except Exception:
        return x


def make_account_key(username: Optional[str], cust_rech_no: str) -> str:
    return md5(f"{username or ''}|{cust_rech_no}")[:16]


def get_state_dir() -> Path:
    return Path(os.getenv("DRJF_STATE_DIR") or "./drjf_state")


def load_runtime_state(state_dir: Path) -> dict:
    state_file = state_dir / "state.json"
    if not state_file.exists():
        return {"version": 1, "meta": {}, "accounts": {}}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("state root is not dict")
    except Exception as exc:
        print(f"[WARN] 状态文件读取失败，已忽略: {state_file} -> {exc}")
        return {"version": 1, "meta": {}, "accounts": {}}
    data.setdefault("version", 1)
    if not isinstance(data.get("meta"), dict):
        data["meta"] = {}
    if not isinstance(data.get("accounts"), dict):
        data["accounts"] = {}
    return data


def save_runtime_state(state_dir: Path, state: dict) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "state.json"
    tmp = state_file.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(state_file)


def _float_changed(a: Optional[float], b: Optional[float], eps: float = 1e-9) -> bool:
    if a is None and b is None:
        return False
    if a is None or b is None:
        return True
    return abs(float(a) - float(b)) > eps


def _trim_history_items(items: List[dict], now_ts: int) -> List[dict]:
    keep_after = now_ts - 90 * 86400
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ts = int(it.get("ts") or 0) if str(it.get("ts") or "").strip() else 0
        if ts >= keep_after:
            out.append(it)
    out.sort(key=lambda x: int(x.get("ts") or 0))
    if len(out) > 1500:
        out = out[-1500:]
    return out


def update_state_with_result(state: dict, result: "JobResult", low_threshold: Optional[float]) -> None:
    if not isinstance(state, dict):
        return
    accounts = state.setdefault("accounts", {})
    if not isinstance(accounts, dict):
        state["accounts"] = {}
        accounts = state["accounts"]

    key = result.account_key or make_account_key(None, result.cust_rech_no)
    acc = accounts.get(key)
    if not isinstance(acc, dict):
        acc = {}
        accounts[key] = acc

    acc["label"] = result.label
    acc["custRechNo"] = result.cust_rech_no
    acc["usernameMasked"] = result.username_masked

    if not result.ok:
        return

    prev = acc.get("last_success") if isinstance(acc.get("last_success"), dict) else None
    change_parts: List[str] = []
    if prev is None:
        result.data_changed = True
        result.change_summary = "首次记录"
    else:
        prev_balance = safe_float(prev.get("balance_num"))
        prev_power = safe_float(prev.get("power_num"))
        prev_subsidy = safe_float(prev.get("subsidy_num"))

        if _float_changed(prev_power, result.power_num):
            change_parts.append(f"电量 {prev_power if prev_power is not None else '-'}→{result.power_raw if result.power_raw is not None else '-'}")
        if _float_changed(prev_balance, result.balance_num):
            change_parts.append(f"余额 {prev_balance if prev_balance is not None else '-'}→{result.balance_raw if result.balance_raw is not None else '-'}")
        if _float_changed(prev_subsidy, result.subsidy_num):
            change_parts.append(f"补助 {prev_subsidy if prev_subsidy is not None else '-'}→{result.subsidy_raw if result.subsidy_raw is not None else '-'}")

        result.data_changed = bool(change_parts)
        if change_parts:
            result.change_summary = "；".join(change_parts)

    threshold_value = result.power_num if result.power_num is not None else result.balance_num
    result.threshold_value = threshold_value
    low_active_prev = bool(acc.get("low_active", False))
    low_active_now = False
    low_triggered = False
    if low_threshold is not None and threshold_value is not None and threshold_value < low_threshold:
        low_active_now = True
        low_triggered = (not low_active_prev) or bool(result.data_changed)
    result.low_active = low_active_now
    result.low_triggered = low_triggered
    acc["low_active"] = low_active_now

    now_ts = int(time.time())
    sample = {
        "ts": now_ts,
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now_ts)),
        "balance_num": result.balance_num,
        "power_num": result.power_num,
        "subsidy_num": result.subsidy_num,
    }
    history = acc.get("history") if isinstance(acc.get("history"), list) else []
    history.append(sample)
    acc["history"] = _trim_history_items(history, now_ts)

    acc["last_success"] = {
        "ts": now_ts,
        "time": sample["time"],
        "balance_num": result.balance_num,
        "power_num": result.power_num,
        "subsidy_num": result.subsidy_num,
        "apartment": result.apartment,
        "balance_raw": result.balance_raw,
        "power_raw": result.power_raw,
        "subsidy_raw": result.subsidy_raw,
    }


def _calc_weekly_power_stats(history: List[dict], now_ts: int) -> Optional[dict]:
    items: List[dict] = []
    start_ts = now_ts - 8 * 86400
    for it in history:
        if not isinstance(it, dict):
            continue
        ts = int(it.get("ts") or 0) if str(it.get("ts") or "").strip() else 0
        if ts <= 0 or ts < start_ts:
            continue
        items.append({
            "ts": ts,
            "power_num": safe_float(it.get("power_num")),
            "balance_num": safe_float(it.get("balance_num")),
        })
    if not items:
        return None
    items.sort(key=lambda x: x["ts"])

    consumed = 0.0
    recharged = 0.0
    usable_pairs = 0
    for prev, cur in zip(items, items[1:]):
        p1 = prev.get("power_num")
        p2 = cur.get("power_num")
        if p1 is None or p2 is None:
            continue
        usable_pairs += 1
        delta = float(p1) - float(p2)
        if delta > 0:
            consumed += delta
        elif delta < 0:
            recharged += -delta

    first_power = next((it.get("power_num") for it in items if it.get("power_num") is not None), None)
    last_power = next((it.get("power_num") for it in reversed(items) if it.get("power_num") is not None), None)
    net_drop = None
    if first_power is not None and last_power is not None:
        net_drop = float(first_power) - float(last_power)

    return {
        "samples": len(items),
        "usable_pairs": usable_pairs,
        "consumed": consumed,
        "recharged": recharged,
        "net_drop": net_drop,
        "current_power": last_power,
    }


def build_weekly_stats_section(results: List["JobResult"], state: dict, enabled: bool, notify_weekday: int) -> Tuple[str, bool]:
    if not enabled:
        return "", False

    now = datetime.now()
    if now.weekday() != notify_weekday:
        return "", False

    if not isinstance(state, dict):
        return "", False
    meta = state.setdefault("meta", {})
    if not isinstance(meta, dict):
        state["meta"] = {}
        meta = state["meta"]

    iso = now.isocalendar()
    week_key = f"{iso.year}-W{int(iso.week):02d}"
    if str(meta.get("weekly_last_sent_week") or "") == week_key:
        return "", False

    accounts = state.get("accounts") if isinstance(state.get("accounts"), dict) else {}
    now_ts = int(time.time())

    lines: List[str] = []
    lines.append("--- 每周用电统计（近7天估算）---")
    lines.append(f"统计周: {week_key}")

    for r in results:
        key = r.account_key or make_account_key(None, r.cust_rech_no)
        acc = accounts.get(key) if isinstance(accounts, dict) else None
        history = acc.get("history") if isinstance(acc, dict) and isinstance(acc.get("history"), list) else []
        stats = _calc_weekly_power_stats(history, now_ts)
        if not stats or stats.get("samples", 0) < 2:
            lines.append(f"- {r.label} ({r.cust_rech_no}): 样本不足（样本={stats.get('samples', 0) if stats else 0}）")
            continue

        consumed = float(stats.get("consumed") or 0.0)
        recharged = float(stats.get("recharged") or 0.0)
        net_drop = stats.get("net_drop")
        current_power = stats.get("current_power")
        samples = int(stats.get("samples") or 0)
        usable_pairs = int(stats.get("usable_pairs") or 0)

        parts = [f"- {r.label} ({r.cust_rech_no})"]
        parts.append(f"周耗电≈{consumed:.2f}度")
        if recharged > 0:
            parts.append(f"期间回升/充值≈+{recharged:.2f}度")
        if net_drop is not None:
            sign = "" if float(net_drop) >= 0 else "+"
            parts.append(f"净变化={sign}{float(net_drop):.2f}度(正数=下降)")
        if current_power is not None:
            parts.append(f"当前电量={float(current_power):.2f}度")
        parts.append(f"样本={samples}, 有效区间={usable_pairs}")
        lines.append(" | ".join(parts))

    meta["weekly_last_sent_week"] = week_key
    return "\n" + "\n".join(lines) + "\n", True


def mask_username(u: str) -> str:
    if not u:
        return "<empty>"
    if len(u) <= 4:
        return u[0] + "***"
    return u[:2] + "***" + u[-2:]


# =========================
# 密码加密（SM2）
# =========================

def encrypt_pwd_for_login(password: str, public_key_hex: str = PUBKEY) -> dict:
    if sm2 is None:
        raise RuntimeError(f"缺少 gmssl 依赖，无法进行 SM2 加密: {_GMSSL_IMPORT_ERROR}")

    ts_ms = int(time.time() * 1000)
    pwd_plain = f"{password}|{ts_ms}"
    msg_bytes = base64.b64encode(pwd_plain.encode("utf-8"))

    pub = public_key_hex.strip().lower()
    if len(pub) > 128:
        pub = pub[-128:]
    if len(pub) != 128:
        raise ValueError(f"公钥长度异常，处理后应为128 hex，当前={len(pub)}")

    try:
        crypt = sm2.CryptSM2(public_key=pub, private_key="", mode=1)
    except TypeError:
        crypt = sm2.CryptSM2(public_key=pub, private_key="")

    enc = crypt.encrypt(msg_bytes)
    cipher_hex = enc.hex().lower() if isinstance(enc, (bytes, bytearray)) else str(enc).strip().lower()
    if cipher_hex.startswith("04"):
        cipher_hex = cipher_hex[2:]
    pwd_encrypted = "04" + cipher_hex

    return {
        "pwd_plain": pwd_plain,
        "pwd_encrypted": pwd_encrypted,
        "ts_ms": ts_ms,
    }


# =========================
# 会话文件处理
# =========================

def load_session_cookies(session: Session, session_file: Path) -> Optional[str]:
    payload = json.loads(session_file.read_text(encoding="utf-8"))
    cookies = payload.get("cookies", [])
    session_cookie = None

    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        domain = cookie.get("domain") or HOST
        if not name or value is None:
            continue
        session.cookies.set(name, value, domain=domain, path=cookie.get("path", "/"))
        if str(name).upper() == "SESSION" and HOST in str(domain):
            session_cookie = value
    return session_cookie


def extract_defaults_from_session(session_file: Path) -> dict:
    payload = json.loads(session_file.read_text(encoding="utf-8"))
    session_storage = payload.get("sessionStorage", {}) if isinstance(payload, dict) else {}
    captured_sessiontoken = payload.get("capturedSessionToken") if isinstance(payload, dict) else None

    login_data = parse_json_or_empty(session_storage.get("loginData") if isinstance(session_storage, dict) else None)
    site_info = parse_json_or_empty(session_storage.get("siteInfo") if isinstance(session_storage, dict) else None)

    session_cookie = None
    for cookie in payload.get("cookies", []) if isinstance(payload, dict) else []:
        if str(cookie.get("name", "")).upper() == "SESSION" and HOST in str(cookie.get("domain") or ""):
            session_cookie = cookie.get("value")
            break

    sessiontoken = captured_sessiontoken or site_info.get("sessionToken") or decode_session_cookie(session_cookie)

    return {
        "userInfoId": login_data.get("userInfoId"),
        "merchantId": site_info.get("current_merchant_id") or DEFAULT_MERCHANT_ID,
        "sessiontoken": sessiontoken,
    }


def dump_session_file(
    session: Session,
    session_file: Path,
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

    data_json = login_data if isinstance(login_data, dict) else {}
    payload = {
        "url": final_url,
        "cookies": cookies_payload,
        "localStorage": {},
        "sessionStorage": {
            "loginData": json.dumps(data_json, ensure_ascii=False),
            "siteInfo": json.dumps(site_info if isinstance(site_info, dict) else {}, ensure_ascii=False),
        },
        "capturedSessionToken": captured_sessiontoken,
        "requestLogin": {"pwd_plain": pwd_plain},
    }
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


# =========================
# 接口调用（查询/登录）
# =========================

def query_electricity(
    session: Session,
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
        "origin": BASE,
        "referer": f"{BASE}/",
        "requestsitedomain": HOST,
        "requestid": sign["requestid"],
        "rand": sign["rand"],
        "token": sign["token"],
        "sessiontoken": sessiontoken,
        "user-agent": UA,
    }
    resp = session.post(API_SELECT_AND_CHECK_ORDER, headers=headers, json=body, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _normalize_referer(url: str) -> str:
    parsed = urlparse(url)
    return url if (parsed.scheme and parsed.netloc) else f"{BASE}/"


def build_redirect_uri(service: str) -> str:
    service_with_sso = f"{service}?ssoType=true"
    service_encoded = quote(service_with_sso, safe="")
    return f"https://{HOST}:443/api/user/ssoRedirect.do?service={service_encoded}"


def run_sso_login_flow(session: Session, timeout: int, service: str) -> Tuple[str, str]:
    # 先登出，清理状态（失败无所谓）
    try:
        session.post(
            f"{SSO}/oauth2.0/logout?service=",
            json={"service": service},
            headers={"content-type": "application/json;charset=UTF-8", "referer": f"{BASE}/", "user-agent": UA},
            timeout=timeout,
        )
    except Exception as exc:
        dprint("logout ignore:", exc)

    redirect_raw = build_redirect_uri(service)
    redirect_param = quote(redirect_raw, safe="")
    rand = uuid.uuid4().hex
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


def post_login(session: Session, username: str, password: str, service: str, referer: str, timeout: int) -> Tuple[dict, str]:
    enc = encrypt_pwd_for_login(password)
    payload = {"userName": username, "pwd": enc["pwd_encrypted"], "service": service}
    headers = {
        "content-type": "application/json;charset=UTF-8",
        "accept": "application/json, text/plain, */*",
        "origin": BASE,
        "referer": _normalize_referer(referer),
        "user-agent": UA,
    }
    r = session.post(f"{SSO}/oauth2.0/loginSubmit", json=payload, headers=headers, timeout=timeout)
    r.raise_for_status()
    try:
        return r.json(), enc["pwd_plain"]
    except Exception:
        return {"raw": r.text}, enc["pwd_plain"]


def finalize_sso(session: Session, login_page_url: str, auth_post_url: str, timeout: int) -> str:
    r = session.get(
        auth_post_url,
        headers={"referer": _normalize_referer(login_page_url), "user-agent": UA},
        allow_redirects=True,
        timeout=timeout,
    )
    r.raise_for_status()
    return r.url


def fetch_user_base_info(session: Session, timeout_seconds: int) -> dict:
    r = session.get(
        API_GET_USER_BASE,
        headers={"accept": "application/json, text/plain, */*", "referer": f"{BASE}/", "user-agent": UA},
        timeout=timeout_seconds,
    )
    r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def fetch_site_info(session: Session, timeout_seconds: int, final_url: str, session_token: str) -> dict:
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
        "user-agent": UA,
    }
    r = session.post(API_FIRST_INTERFACE, headers=headers, json=payload, timeout=timeout_seconds)
    r.raise_for_status()
    try:
        site_info = r.json()
    except Exception:
        return {}
    return site_info if isinstance(site_info, dict) else {}


def login_and_dump_session(
    username: str,
    password: str,
    timeout: int,
    session_file: Path,
    service: str = BASE,
) -> dict:
    with requests.Session() as s:
        login_page_url, auth_post_url = run_sso_login_flow(s, timeout, service)
        result, plain = post_login(s, username, password, service, login_page_url, timeout)

        code = str(result.get("code", "")).strip()
        if code != "00000000":
            return {
                "success": False,
                "loginResult": result,
                "message": f"登录失败（code={code or '<empty>'}）",
                "raw": result,
            }

        final_url = finalize_sso(s, login_page_url, auth_post_url, timeout)

        user_base = fetch_user_base_info(s, timeout)
        if not isinstance(user_base, dict) or str(user_base.get("code", "")).strip() != "00000000":
            return {
                "success": False,
                "loginResult": result,
                "message": f"获取用户信息失败（code={str(user_base.get('code', '')) if isinstance(user_base, dict) else '<non-dict>'}）",
                "raw": user_base,
            }

        user_base_data = user_base.get("data_json")
        if not isinstance(user_base_data, dict):
            return {
                "success": False,
                "loginResult": result,
                "message": "获取用户信息失败（缺少标准字段 data_json）",
                "raw": user_base,
            }

        session_token = str(user_base_data.get("sessionToken") or "").strip()
        if not session_token:
            return {
                "success": False,
                "loginResult": result,
                "message": "获取用户信息失败（缺少标准字段 data_json.sessionToken）",
                "raw": user_base,
            }


        site_info = fetch_site_info(s, timeout, final_url, session_token)
        if not site_info:
            site_info = {
                "is_login": True,
                "current_merchant_id": DEFAULT_MERCHANT_ID,
                "sessionToken": session_token,
            }
        elif not site_info.get("sessionToken"):
            site_info["sessionToken"] = session_token

        dump_session_file(s, session_file, final_url, user_base_data, plain, site_info, session_token)

        return {
            "success": True,
            "loginResult": result,
            "userBaseCode": user_base.get("code") if isinstance(user_base, dict) else None,
            "siteInfoCode": site_info.get("code") if isinstance(site_info, dict) else None,
            "sessionToken": session_token,
            "finalUrl": final_url,
            "cookies": s.cookies.get_dict(),
            "sessionFile": str(session_file.resolve()),
        }


# =========================
# 结果提取与通知
# =========================

def _walk_numbers(obj: Any, path: str = "") -> List[Tuple[str, Any]]:
    items: List[Tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            items.extend(_walk_numbers(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{path}[{i}]"
            items.extend(_walk_numbers(v, p))
    else:
        if isinstance(obj, (int, float, str)):
            if safe_float(obj) is not None:
                items.append((path, obj))
    return items


def extract_balance_info(api_result: dict) -> dict:
    """严格按标准结构解析电费查询返回，不做任何字段猜测。

    标准结构（成功）：
    - type == "S" 且 code == "30300000"
    - datajson.deviceInfo[0].unitValue            -> 剩余电量
    - datajson.deviceInfo[0].infos[*].key=nMoney  -> 当前余额
    - datajson.deviceInfo[0].infos[*].key=bzMoney -> 剩余补助
    """
    out: dict = {"raw": api_result}

    if not isinstance(api_result, dict):
        out["error"] = "响应不是 JSON 对象"
        return out

    code = str(api_result.get("code", "")).strip()
    typ = str(api_result.get("type", "")).strip()
    if not (typ == "S" and code == "30300000"):
        out["error"] = f"非查询成功返回(type={typ or '<empty>'}, code={code or '<empty>'})"
        return out

    data = api_result.get("datajson")
    if not isinstance(data, dict):
        out["error"] = "缺少标准字段 datajson(dict)"
        return out

    device_list = data.get("deviceInfo")
    if not isinstance(device_list, list) or not device_list or not isinstance(device_list[0], dict):
        out["error"] = "缺少标准字段 datajson.deviceInfo[0](dict)"
        return out

    device0 = device_list[0]
    out["roomField"] = data.get("custRechNo")
    out["apartment"] = device0.get("nameValue")

    power_raw = device0.get("unitValue")
    out["power"] = {
        "path": "datajson.deviceInfo[0].unitValue",
        "raw": power_raw,
        "num": safe_float(power_raw),
    }

    money_item = None
    subsidy_item = None
    infos = device0.get("infos")
    if isinstance(infos, list):
        for idx, item in enumerate(infos):
            if not isinstance(item, dict):
                continue
            k = str(item.get("key", "")).strip()
            if k == "nMoney" and money_item is None:
                money_item = {
                    "path": f"datajson.deviceInfo[0].infos[{idx}]",
                    "raw": item,
                    "num": safe_float(item.get("keyValue")),
                    "value_path": f"datajson.deviceInfo[0].infos[{idx}].keyValue",
                    "value_raw": item.get("keyValue"),
                    "name": item.get("keyName"),
                }
            elif k == "bzMoney" and subsidy_item is None:
                subsidy_item = {
                    "path": f"datajson.deviceInfo[0].infos[{idx}]",
                    "raw": item,
                    "num": safe_float(item.get("keyValue")),
                    "value_path": f"datajson.deviceInfo[0].infos[{idx}].keyValue",
                    "value_raw": item.get("keyValue"),
                    "name": item.get("keyName"),
                }

    out["money"] = money_item
    out["subsidy"] = subsidy_item

    # 兼容现有主流程：candidate 默认取当前余额 nMoney；没有时回退剩余电量 unitValue
    if money_item is not None:
        out["candidate"] = {
            "path": money_item.get("value_path"),
            "raw": money_item.get("value_raw"),
            "num": money_item.get("num"),
        }
    else:
        out["candidate"] = out["power"]

    return out


def ql_send(title: str, content: str) -> None:
    try:
        QLAPI.notify(title, content)
        return
    except Exception as e:
        print(repr(e))
        pass

    # 兜底：控制台输出
    print(f"\n===== {title} =====\n{content}\n")


# =========================
# 配置与执行模型
# =========================
@dataclass
class JobConfig:
    username: Optional[str]
    password: Optional[str]
    cust_rech_no: str
    label: str
    session_file: Path
    timeout: int = 20
    login_timeout: int = 20
    merchant_id: Optional[int] = None
    user_info_id: Optional[int] = None
    rech_mer_map_id: int = DEFAULT_RECH_MER_MAP_ID
    sessiontoken: str = ""


@dataclass
class JobResult:
    ok: bool
    label: str
    cust_rech_no: str
    username_masked: str
    message: str
    balance_num: Optional[float] = None
    balance_raw: Optional[Any] = None
    balance_path: Optional[str] = None
    power_num: Optional[float] = None
    power_raw: Optional[Any] = None
    power_path: Optional[str] = None
    subsidy_num: Optional[float] = None
    subsidy_raw: Optional[Any] = None
    subsidy_path: Optional[str] = None
    apartment: Optional[str] = None
    parse_error: Optional[str] = None
    raw_result: Optional[dict] = None
    login_refreshed: bool = False
    account_key: Optional[str] = None
    data_changed: bool = False
    change_summary: Optional[str] = None
    low_active: bool = False
    low_triggered: bool = False
    threshold_value: Optional[float] = None


def make_session_file(session_dir: Path, username: str, cust_rech_no: str) -> Path:
    # 避免明文账号作为文件名带来的特殊字符问题
    key = md5(f"{username}|{cust_rech_no}")[:16]
    safe_room = re.sub(r"[^a-zA-Z0-9_.-]+", "_", cust_rech_no)
    return session_dir / f"drjf_{safe_room}_{key}.json"


def split_multi_accounts(raw: str) -> List[str]:
    raw = raw.strip()
    if not raw:
        return []
    if "\n" in raw:
        return [x.strip() for x in raw.splitlines() if x.strip()]
    if "&" in raw:
        return [x.strip() for x in raw.split("&") if x.strip()]
    # 单条
    return [raw]


def parse_account_line(line: str) -> Tuple[str, str, str, str]:
    # 支持 , @ # | 任一分隔；优先逗号
    if "," in line:
        parts = [x.strip() for x in line.split(",")]
    elif "@" in line:
        parts = [x.strip() for x in line.split("@")]
    elif "#" in line:
        parts = [x.strip() for x in line.split("#")]
    elif "|" in line:
        parts = [x.strip() for x in line.split("|")]
    else:
        raise ValueError("账号格式错误，需为 用户名,密码,寝室号[,备注]")
    if len(parts) < 3:
        raise ValueError("账号字段不足，至少需要 用户名,密码,寝室号")
    username, password, room = parts[0], parts[1], parts[2]
    label = parts[3] if len(parts) >= 4 and parts[3] else room
    return username, password, room, label


def load_json_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[WARN] 配置文件解析失败，忽略: {p} -> {e}")
        return {}


def resolve_jobs() -> Tuple[List[JobConfig], dict]:
    cfg_path = os.getenv("DRJF_CONFIG")
    cfg = load_json_config(cfg_path)

    session_dir = Path(
        os.getenv("DRJF_SESSION_DIR")
        or cfg.get("sessionDir")
        or "./drjf_sessions"
    )

    timeout = int(parse_int_env("DRJF_TIMEOUT", None) or cfg.get("timeout") or 20)
    login_timeout = int(parse_int_env("DRJF_LOGIN_TIMEOUT", None) or cfg.get("loginTimeout") or 20)
    default_rech_map_id = int(
        parse_int_env("DRJF_RECH_MER_MAP_ID", None)
        or cfg.get("rechMerMapId")
        or DEFAULT_RECH_MER_MAP_ID
    )
    _env_merchant_id = parse_int_env("DRJF_MERCHANT_ID", None)
    default_merchant_id = _env_merchant_id if _env_merchant_id is not None else cfg.get("merchantId")
    _env_user_info_id = parse_int_env("DRJF_USER_INFO_ID", None)
    default_user_info_id = _env_user_info_id if _env_user_info_id is not None else cfg.get("userInfoId")
    default_sessiontoken = str(os.getenv("DRJF_SESSIONTOKEN") or cfg.get("sessiontoken") or "")

    jobs: List[JobConfig] = []

    # 1) 多账号 env
    accounts_raw = os.getenv("DRJF_ACCOUNTS", "").strip()
    if accounts_raw:
        for idx, line in enumerate(split_multi_accounts(accounts_raw), start=1):
            username, password, room, label = parse_account_line(line)
            session_file = make_session_file(session_dir, username, room)
            jobs.append(
                JobConfig(
                    username=username,
                    password=password,
                    cust_rech_no=room,
                    label=label or f"账号{idx}",
                    session_file=session_file,
                    timeout=timeout,
                    login_timeout=login_timeout,
                    merchant_id=default_merchant_id,
                    user_info_id=default_user_info_id,
                    rech_mer_map_id=default_rech_map_id,
                    sessiontoken=default_sessiontoken,
                )
            )

    # 2) 单账号（env / JSON config）
    if not jobs:
        username = os.getenv("DRJF_USERNAME") or cfg.get("username")
        password = os.getenv("DRJF_PASSWORD") or cfg.get("password")
        room = os.getenv("DRJF_CUST_RECH_NO") or cfg.get("custRechNo")
        label = str(os.getenv("DRJF_LABEL") or cfg.get("label") or room or "电费查询")
        if not room:
            raise SystemExit("[ERROR] 未提供寝室号。请设置 DRJF_ACCOUNTS 或 DRJF_CUST_RECH_NO")

        session_file = (
            Path(os.getenv("DRJF_SESSION_FILE"))
            if os.getenv("DRJF_SESSION_FILE")
            else make_session_file(session_dir, str(username or "anonymous"), str(room))
        )
        jobs.append(
            JobConfig(
                username=username,
                password=password,
                cust_rech_no=str(room),
                label=label,
                session_file=session_file,
                timeout=timeout,
                login_timeout=login_timeout,
                merchant_id=default_merchant_id,
                user_info_id=default_user_info_id,
                rech_mer_map_id=default_rech_map_id,
                sessiontoken=default_sessiontoken,
            )
        )

    return jobs, cfg


def do_query_once(job: JobConfig) -> dict:
    with requests.Session() as session:
        load_session_cookies(session, job.session_file)
        return query_electricity(
            session=session,
            merchant_id=ensure_int(job.merchant_id, "merchantId"),
            user_info_id=ensure_int(job.user_info_id, "userInfoId"),
            rech_mer_map_id=ensure_int(job.rech_mer_map_id, "rechMerMapId"),
            cust_rech_no=job.cust_rech_no,
            sessiontoken=str(job.sessiontoken or ""),
            timeout=ensure_int(job.timeout, "timeout"),
        )


def login_refresh(job: JobConfig) -> dict:
    if not job.username or not job.password:
        return {"success": False, "message": "会话过期且未提供账号密码，无法自动登录"}
    out = login_and_dump_session(
        username=job.username,
        password=job.password,
        timeout=max(5, int(job.login_timeout)),
        session_file=job.session_file,
        service=BASE,
    )
    return out if isinstance(out, dict) else {"success": False, "message": "登录返回异常", "raw": out}


def enrich_from_session_defaults(job: JobConfig) -> None:
    if not job.session_file.exists():
        return
    try:
        d = extract_defaults_from_session(job.session_file)
    except Exception as exc:
        dprint("extract_defaults_from_session failed:", exc)
        return
    if not job.user_info_id and d.get("userInfoId") is not None:
        job.user_info_id = d.get("userInfoId")
    if not job.merchant_id and d.get("merchantId") is not None:
        job.merchant_id = d.get("merchantId")
    if not job.sessiontoken and d.get("sessiontoken"):
        job.sessiontoken = str(d.get("sessiontoken"))


def execute_job(job: JobConfig) -> JobResult:
    username_masked = mask_username(job.username or "")
    login_refreshed = False

    try:
        enrich_from_session_defaults(job)

        need_login = False
        if not job.session_file.exists():
            dprint(job.label, "session file not found")
            need_login = True
        if not job.user_info_id:
            dprint(job.label, "userInfoId missing")
            need_login = True

        # 会话预检测（只有具备查询参数时才做）
        if not need_login:
            try:
                pre = do_query_once(job)
                if looks_like_query_success(pre):
                    info = extract_balance_info(pre)
                    cand = info.get("candidate") or {}
                    pwr = info.get("power") or {}
                    sub = info.get("subsidy") or {}
                    parse_error = info.get("error")
                    if parse_error:
                        return JobResult(
                            ok=False,
                            label=job.label,
                            cust_rech_no=job.cust_rech_no,
                            username_masked=username_masked,
                            message=f"查询成功但结构不符合标准: {parse_error}",
                            raw_result=pre,
                            parse_error=parse_error,
                            login_refreshed=False,
                        )
                    return JobResult(
                        ok=True,
                        label=job.label,
                        cust_rech_no=job.cust_rech_no,
                        username_masked=username_masked,
                        message="查询成功（复用会话）",
                        balance_num=cand.get("num"),
                        balance_raw=cand.get("raw"),
                        balance_path=cand.get("path"),
                        power_num=pwr.get("num"),
                        power_raw=pwr.get("raw"),
                        power_path=pwr.get("path"),
                        subsidy_num=sub.get("num"),
                        subsidy_raw=sub.get("value_raw"),
                        subsidy_path=sub.get("value_path"),
                        apartment=info.get("apartment"),
                        raw_result=pre,
                        login_refreshed=False,
                    )
                if looks_like_auth_expired(pre):
                    need_login = True
                else:
                    return JobResult(
                        ok=False,
                        label=job.label,
                        cust_rech_no=job.cust_rech_no,
                        username_masked=username_masked,
                        message=f"查询失败（type={pre.get('type') or '<empty>'}, code={pre.get('code') or '<empty>'}）",
                        raw_result=pre,
                        login_refreshed=False,
                    )
            except requests.RequestException as exc:
                dprint(job.label, "precheck request exception", exc)
                need_login = True

        if need_login:
            login_out = login_refresh(job)
            if not login_out.get("success"):
                return JobResult(
                    ok=False,
                    label=job.label,
                    cust_rech_no=job.cust_rech_no,
                    username_masked=username_masked,
                    message=str(login_out.get("message") or "登录失败"),
                    raw_result=login_out.get("raw") if isinstance(login_out.get("raw"), dict) else (login_out if isinstance(login_out, dict) else None),
                    login_refreshed=False,
                )
            login_refreshed = True
            enrich_from_session_defaults(job)
            if not job.user_info_id:
                raise RuntimeError("自动登录后仍无法获取 userInfoId")

        # 正式查询（登录后 / 无预检测）
        result = do_query_once(job)
        if not looks_like_query_success(result):
            return JobResult(
                ok=False,
                label=job.label,
                cust_rech_no=job.cust_rech_no,
                username_masked=username_masked,
                message=(f"查询失败（type={result.get('type') or '<empty>'}, code={result.get('code') or '<empty>'}）" + ("（已自动登录）" if login_refreshed else "")),
                raw_result=result,
                login_refreshed=login_refreshed,
            )

        info = extract_balance_info(result)
        parse_error = info.get("error")
        if parse_error:
            return JobResult(
                ok=False,
                label=job.label,
                cust_rech_no=job.cust_rech_no,
                username_masked=username_masked,
                message=(f"查询成功但结构不符合标准: {parse_error}" + ("（已自动登录）" if login_refreshed else "")),
                raw_result=result,
                parse_error=parse_error,
                login_refreshed=login_refreshed,
            )

        cand = info.get("candidate") or {}
        pwr = info.get("power") or {}
        sub = info.get("subsidy") or {}
        return JobResult(
            ok=True,
            label=job.label,
            cust_rech_no=job.cust_rech_no,
            username_masked=username_masked,
            message=("查询成功" + ("（已自动登录）" if login_refreshed else "")),
            balance_num=cand.get("num"),
            balance_raw=cand.get("raw"),
            balance_path=cand.get("path"),
            power_num=pwr.get("num"),
            power_raw=pwr.get("raw"),
            power_path=pwr.get("path"),
            subsidy_num=sub.get("num"),
            subsidy_raw=sub.get("value_raw"),
            subsidy_path=sub.get("value_path"),
            apartment=info.get("apartment"),
            raw_result=result,
            login_refreshed=login_refreshed,
        )

    except Exception as exc:
        dprint(traceback.format_exc())
        return JobResult(
            ok=False,
            label=job.label,
            cust_rech_no=job.cust_rech_no,
            username_masked=username_masked,
            message=f"执行异常: {exc}",
            raw_result=None,
            login_refreshed=login_refreshed,
        )


def build_notify_content(results: List[JobResult], low_threshold: Optional[float]) -> Tuple[str, str]:
    success_count = sum(1 for r in results if r.ok)
    fail_count = len(results) - success_count

    title = f"东软电费查询 | 成功{success_count} 失败{fail_count}"
    lines: List[str] = []
    lines.append(f"执行时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    for i, r in enumerate(results, start=1):
        prefix = "✅" if r.ok else "❌"
        extras: List[str] = []
        threshold_value = r.power_num if r.power_num is not None else r.balance_num
        if r.ok and threshold_value is not None and low_threshold is not None and threshold_value < low_threshold:
            extras.append("⚠️低于阈值")
        if r.ok and r.data_changed:
            extras.append("变更")
        if r.ok and r.low_triggered:
            extras.append("低阈值触发")
        extra = (" " + " ".join(extras)) if extras else ""
        lines.append(f"{prefix} [{i}] {r.label} {extra}")
        #lines.append(f"{prefix} [{i}] {r.label} ({r.cust_rech_no}){extra}")
        #lines.append(f"   账号: {r.username_masked or '-'}")
        lines.append(f"   结果: {r.message}")
        if r.ok and r.change_summary:
            lines.append(f"   数据变更: {r.change_summary}")
        if r.apartment:
            lines.append(f"   宿舍信息: {r.apartment}")
        elif r.balance_raw is not None:
            lines.append(f"   当前余额: {r.balance_raw}")
        elif r.power_raw is not None:
            lines.append(f"   剩余电量: {r.power_raw}")
        elif r.subsidy_raw is not None:
            lines.append(f"   剩余补助: {r.subsidy_raw}")
        if not r.ok and r.raw_result:
            msg = r.raw_result.get("message") or r.raw_result.get("msg") or r.raw_result.get("code")
            if msg:
                lines.append(f"   接口返回: {msg}")
        lines.append("")

    # 附加原始输出（仅失败项，避免通知过长）
    fail_raws = [r for r in results if (not r.ok and r.raw_result)]
    if fail_raws:
        lines.append("--- 失败项原始返回（截断）---")
        for r in fail_raws[:3]:
            raw = fmt_json(r.raw_result)
            if len(raw) > 1200:
                raw = raw[:1200] + "\n...(truncated)"
            lines.append(f"[{r.label}/{r.cust_rech_no}]\n{raw}")
            lines.append("")

    return title, "\n".join(lines).rstrip() + "\n"


# =========================
# Main（仅环境变量）
# =========================

def main() -> int:
    jobs, _cfg = resolve_jobs()
    low_threshold = None
    raw_low = os.getenv("DRJF_LOW_THRESHOLD", "").strip()
    if raw_low:
        low_threshold = safe_float(raw_low)

    notify_enabled = parse_bool_env("DRJF_NOTIFY", True)
    notify_only_fail = parse_bool_env("DRJF_NOTIFY_ONLY_FAIL", False)
    notify_on_change = parse_bool_env("DRJF_NOTIFY_ON_CHANGE", True)
    weekly_stats_enabled = parse_bool_env("DRJF_WEEKLY_STATS", True)
    weekly_notify_weekday = parse_int_env("DRJF_WEEKLY_NOTIFY_WEEKDAY", 0)
    if weekly_notify_weekday is None or weekly_notify_weekday < 0 or weekly_notify_weekday > 6:
        weekly_notify_weekday = 0

    state_dir = get_state_dir()
    state = load_runtime_state(state_dir)

    print(f"[INFO] 待执行账号数: {len(jobs)}")

    results: List[JobResult] = []
    for idx, job in enumerate(jobs, start=1):
        print(f"\n[INFO] ({idx}/{len(jobs)}) 开始: {job.label} | 寝室={job.cust_rech_no} | 用户={mask_username(job.username or '')}")
        res = execute_job(job)
        res.account_key = make_account_key(job.username, job.cust_rech_no)
        update_state_with_result(state, res, low_threshold)
        results.append(res)

        status = "OK" if res.ok else "FAIL"
        _show_num = res.power_num if res.power_num is not None else res.balance_num
        bal = f" | 数值={_show_num:g}" if _show_num is not None else ""
        flags = []
        if res.ok and res.data_changed:
            flags.append("变更")
        if res.ok and res.low_triggered:
            flags.append("低阈值触发")
        flag_text = (" | " + ",".join(flags)) if flags else ""
        print(f"[{status}] {res.label}({res.cust_rech_no}) -> {res.message}{bal}{flag_text}")

        if parse_bool_env("DRJF_RAW", False) and res.raw_result is not None:
            print(fmt_json(res.raw_result))

    weekly_section, weekly_triggered = build_weekly_stats_section(
        results=results,
        state=state,
        enabled=weekly_stats_enabled,
        notify_weekday=int(weekly_notify_weekday),
    )

    try:
        save_runtime_state(state_dir, state)
    except Exception as exc:
        print(f"[WARN] 保存状态失败: {exc}")

    title, content = build_notify_content(results, low_threshold)
    if weekly_section:
        content = content.rstrip() + "\n\n" + weekly_section.strip() + "\n"

    any_fail = any(not r.ok for r in results)
    any_change = any(r.ok and r.data_changed for r in results)
    any_low_trigger = any(r.ok and r.low_triggered for r in results)

    should_notify_success = True
    if notify_on_change:
        should_notify_success = any_change or any_low_trigger or weekly_triggered

    if notify_enabled:
        if any_fail:
            ql_send(title, content)
        elif (not notify_only_fail) and should_notify_success:
            ql_send(title, content)

    # 控制台也输出汇总（便于不依赖通知模块）
    print("\n===== 汇总 =====")
    print(content)

    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
