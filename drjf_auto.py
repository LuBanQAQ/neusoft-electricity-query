import argparse
import json
import os
import time
from pathlib import Path

import requests

from drjf_sign import (
    extract_defaults_from_session,
    load_session_cookies,
    query_electricity,
)
from login_requests import login_and_dump_session


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="全自动电费查询：先检测会话，过期自动登录，再查询（无 GUI）")
    parser.add_argument("--config", default="drjf_config.json", help="配置文件路径（JSON）")
    parser.add_argument("custRechNo", nargs="?", help="寝室号，如 7-A608")
    parser.add_argument("--custRechNo", dest="custRechNoOpt", default=None, help="寝室号，如 7-A608")

    parser.add_argument("--session-file", default=None, help="会话文件路径")
    parser.add_argument("--username", default=None, help="登录账号")
    parser.add_argument("--password", default=None, help="登录密码")

    parser.add_argument("--merchantId", type=int, default=None)
    parser.add_argument("--userInfoId", type=int, default=None)
    parser.add_argument("--rechMerMapId", type=int, default=None)
    parser.add_argument("--sessiontoken", default=None, help="可手动覆盖请求头 sessiontoken")

    parser.add_argument("--timeout", type=int, default=None, help="查询接口超时（秒）")
    parser.add_argument("--login-timeout", type=int, default=None, help="登录超时（秒）")
    parser.add_argument("--query-retry", type=int, default=None, help="查询重试次数（默认 3）")
    parser.add_argument("--retry-sleep", type=int, default=None, help="每次重试间隔秒数（默认 2）")
    return parser


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


def looks_like_success(result: dict) -> bool:
    code = str(result.get("code", "")).strip()
    if code in {"00000000", "0", "200", "30300000"}:
        return True
    if result.get("success") is True:
        return True
    if str(result.get("type", "")).strip().upper() == "S":
        return True
    return False


def looks_like_upstream_fail(result: dict) -> bool:
    code = str(result.get("code", "")).strip().upper()
    typ = str(result.get("type", "")).strip().upper()
    msg = str(result.get("message", ""))
    if code == "E99999":
        return True
    if typ in {"W", "E"} and ("第三方接口响应" in msg or "接口名称" in msg or "TopUpQueryInterface" in msg):
        return True
    return False


def session_file_exists(path: str) -> bool:
    return Path(path).exists()


def resolve_runtime_path(path_str: str) -> Path:
    candidate = Path(path_str)
    if candidate.is_absolute():
        return candidate
    if candidate.exists():
        return candidate.resolve()
    script_dir = Path(__file__).resolve().parent
    return (script_dir / candidate).resolve()


def load_config(path: str) -> dict:
    config_path = resolve_runtime_path(path)
    if not config_path.exists():
        return {}
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"[ERROR] 配置文件解析失败: {config_path} -> {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"[ERROR] 配置文件内容必须是 JSON 对象: {config_path}")
    return data


def pick_value(*values, default=None):
    for value in values:
        if value is not None and value != "":
            return value
    return default


def looks_like_placeholder_cust(value: str) -> bool:
    norm = value.strip().lower()
    placeholders = {"宿舍号", "寝室号", "custrechno", "room", "example"}
    return norm in placeholders


def must_int(value: object, name: str) -> int:
    if value is None:
        raise SystemExit(f"[ERROR] 参数 {name} 不能为空")
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise SystemExit(f"[ERROR] 参数 {name} 不是有效整数：{value}")


def resolve_defaults(session_file: str) -> dict:
    if not session_file_exists(session_file):
        return {}
    try:
        return extract_defaults_from_session(session_file)
    except Exception:
        return {}


def do_query(
    session_file: str,
    merchant_id: int,
    user_info_id: int,
    rech_mer_map_id: int,
    cust_rech_no: str,
    sessiontoken: str,
    timeout: int,
) -> dict:
    with requests.Session() as session:
        load_session_cookies(session, session_file)
        return query_electricity(
            session=session,
            merchant_id=merchant_id,
            user_info_id=user_info_id,
            rech_mer_map_id=rech_mer_map_id,
            cust_rech_no=cust_rech_no,
            sessiontoken=sessiontoken,
            timeout=timeout,
        )


def do_query_with_retry(
    session_file: str,
    merchant_id: int,
    user_info_id: int,
    rech_mer_map_id: int,
    cust_rech_no: str,
    sessiontoken: str,
    timeout: int,
    query_retry: int,
    retry_sleep: int,
) -> dict:
    attempts = max(1, query_retry)
    last_result: dict | None = None

    for index in range(attempts):
        try:
            result = do_query(
                session_file=session_file,
                merchant_id=merchant_id,
                user_info_id=user_info_id,
                rech_mer_map_id=rech_mer_map_id,
                cust_rech_no=cust_rech_no,
                sessiontoken=sessiontoken,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            if index == attempts - 1:
                raise
            print(f"[WARN] 查询请求异常（第 {index + 1}/{attempts} 次）：{exc}，{retry_sleep}s 后重试")
            time.sleep(max(0, retry_sleep))
            continue

        last_result = result
        if looks_like_upstream_fail(result) and index < attempts - 1:
            print(f"[WARN] 上游接口暂时失败（第 {index + 1}/{attempts} 次），{retry_sleep}s 后重试")
            time.sleep(max(0, retry_sleep))
            continue
        return result

    return last_result or {}


def auto_login(
    username: str | None,
    password: str | None,
    login_timeout: int,
    session_file: str,
) -> None:
    if not username or not password:
        raise SystemExit("[ERROR] 会话已过期且未提供账号密码。请传 --username/--password，或设置环境变量，或写入配置文件")

    print("[INFO] 尝试 requests+SM2 直连登录...")
    req_login = login_and_dump_session(
        username=username,
        password=password,
        timeout=max(5, login_timeout),
        session_file=session_file,
    )
    if req_login.get("success"):
        print("[OK] requests 直连登录成功。")
        return

    message = req_login.get("message") or "unknown"
    raise SystemExit(f"[ERROR] requests 直连登录失败：{message}")


def main() -> int:
    args = build_parser().parse_args()
    config = load_config(args.config)

    cust_rech_no = pick_value(args.custRechNoOpt, args.custRechNo, config.get("custRechNo"))
    if not cust_rech_no:
        raise SystemExit("[ERROR] 请传寝室号（命令行或配置文件）：例如 drjf_auto.py 7-A608")
    if looks_like_placeholder_cust(str(cust_rech_no)):
        raise SystemExit("[ERROR] 配置文件中的 custRechNo 仍是占位值，请改成真实寝室号，例如 7-A608")

    session_file = str(
        resolve_runtime_path(
            str(pick_value(args.session_file, config.get("sessionFile"), default="session_dump.json"))
        )
    )
    username = pick_value(args.username, os.getenv("LOGIN_USERNAME"), config.get("username"))
    password = pick_value(args.password, os.getenv("LOGIN_PASSWORD"), config.get("password"))
    req_timeout = must_int(pick_value(args.timeout, config.get("timeout"), default=20), "timeout")
    login_timeout = must_int(pick_value(args.login_timeout, config.get("loginTimeout"), default=20), "loginTimeout")
    query_retry = must_int(pick_value(args.query_retry, config.get("queryRetry"), default=3), "queryRetry")
    retry_sleep = must_int(pick_value(args.retry_sleep, config.get("retrySleep"), default=2), "retrySleep")
    rech_mer_map_id = must_int(pick_value(args.rechMerMapId, config.get("rechMerMapId"), default=326), "rechMerMapId")
    manual_sessiontoken = str(pick_value(args.sessiontoken, config.get("sessiontoken"), default=""))

    print(f"[INFO] 使用参数: custRechNo={cust_rech_no}, sessionFile={session_file}")

    defaults = resolve_defaults(session_file)

    resolved_user_info_id = args.userInfoId or defaults.get("userInfoId")
    resolved_merchant_id = args.merchantId or config.get("merchantId") or defaults.get("merchantId") or 113377
    resolved_sessiontoken = manual_sessiontoken or defaults.get("sessiontoken") or ""

    need_login = False

    if not session_file_exists(session_file):
        print("[INFO] 未找到 session 文件，先自动登录。")
        need_login = True
    elif not resolved_user_info_id:
        print("[INFO] 会话信息不完整（缺少 userInfoId），先自动登录。")
        need_login = True

    if not need_login:
        current_user_info_id = must_int(resolved_user_info_id, "userInfoId")
        current_merchant_id = must_int(resolved_merchant_id, "merchantId")
        print("[INFO] 先检测会话是否过期...")
        try:
            precheck = do_query_with_retry(
                session_file=session_file,
                merchant_id=current_merchant_id,
                user_info_id=current_user_info_id,
                rech_mer_map_id=rech_mer_map_id,
                cust_rech_no=cust_rech_no,
                sessiontoken=resolved_sessiontoken,
                timeout=req_timeout,
                query_retry=query_retry,
                retry_sleep=retry_sleep,
            )
            if looks_like_success(precheck):
                print("[OK] 会话有效，直接返回查询结果。")
                print(json.dumps(precheck, ensure_ascii=False, indent=2))
                return 0
            if looks_like_upstream_fail(precheck):
                print("[WARN] 预检遇到上游接口波动，转为自动重新登录后再查询。")
                need_login = True
            if not need_login and looks_like_auth_expired(precheck):
                print("[INFO] 检测到会话疑似过期，开始自动登录。")
                need_login = True
            elif not need_login:
                print("[WARN] 会话检测返回非成功结果，但不像鉴权过期；直接返回该结果。")
                print(json.dumps(precheck, ensure_ascii=False, indent=2))
                return 1
        except requests.RequestException as exc:
            print(f"[WARN] 会话检测请求异常：{exc}，尝试自动登录后重试。")
            need_login = True

    if need_login:
        auto_login(
            username=username,
            password=password,
            login_timeout=login_timeout,
            session_file=session_file,
        )

        defaults = resolve_defaults(session_file)
        resolved_user_info_id = args.userInfoId or defaults.get("userInfoId")
        resolved_merchant_id = args.merchantId or config.get("merchantId") or defaults.get("merchantId") or 113377
        resolved_sessiontoken = manual_sessiontoken or defaults.get("sessiontoken") or ""

        if not resolved_user_info_id:
            raise SystemExit("[ERROR] 自动登录后仍无法获取 userInfoId，请检查 session_dump.json")

        current_user_info_id = must_int(resolved_user_info_id, "userInfoId")
        current_merchant_id = must_int(resolved_merchant_id, "merchantId")

        print("[INFO] 登录完成，开始查询...")
        result = do_query_with_retry(
            session_file=session_file,
            merchant_id=current_merchant_id,
            user_info_id=current_user_info_id,
            rech_mer_map_id=rech_mer_map_id,
            cust_rech_no=cust_rech_no,
            sessiontoken=resolved_sessiontoken,
            timeout=req_timeout,
            query_retry=query_retry,
            retry_sleep=retry_sleep,
        )

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if looks_like_success(result) else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
