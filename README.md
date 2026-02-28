# 大连东软信息学院软件园校区三期电费查询脚本

基于 `requests` + SM2 的大连东软信息学院软件园校区三期电费查询脚本，无需 GUI。

## 文件说明

- `drjf_auto.py`：主入口。自动判断会话是否可用，过期则自动登录，再查询。
- `drjf_sign.py`：仅查询（依赖已有 `session_dump.json`）。
- `login_requests.py`：仅登录并生成 `session_dump.json`。
- `drjf_pwd.py`：登录密码 SM2 加密逻辑。
- `drjf_config.json`：运行配置文件。
- `requirements.txt`：依赖列表。

## 环境要求

- Python 3.10+
- 网络可访问目标站点

## 安装依赖

```bash
pip install -r requirements.txt
```

## 配置文件

编辑 `drjf_config.json`：

```json
{
  "username": "你的账号",
  "password": "你的密码",
  "custRechNo": "楼号-宿舍号",
  "sessionFile": "session_dump.json",
  "merchantId": 113377,
  "userInfoId": null,
  "rechMerMapId": 326,
  "sessiontoken": "",
  "timeout": 20,
  "loginTimeout": 20,
  "queryRetry": 3,
  "retrySleep": 2
}
```

> `custRechNo` 必须为真实寝室号，不能写占位值。

## 推荐用法（全自动）

```bash
python drjf_auto.py
```

行为：

1. 读取配置与会话文件；
2. 尝试用现有会话查询；
3. 若会话过期，自动登录；
4. 登录后再次查询并输出结果 JSON。

## 其他用法

### 1) 只登录

```bash
python login_requests.py --username 你的学号 --password 你的密码
```

### 2) 只查询

```bash
python drjf_sign.py 宿舍号
```

### 3) 命令行覆盖配置

```bash
python drjf_auto.py --custRechNo 宿舍号 --timeout 30
```

## 常见问题

### 1) 提示“寝室号未设置”

- 检查 `drjf_config.json` 里的 `custRechNo` 是否为真实值。
- 不要使用 `宿舍号/寝室号/example` 等占位词。

### 2) 提示“用户名或密码不正确”

- 确认 `username`、`password` 与门户一致。
- 注意是否有空格、全角字符或错误编码。

### 3) 偶发查询失败（如上游接口波动）

- 增大 `queryRetry` 和 `retrySleep`。
- 例如：`queryRetry: 5`、`retrySleep: 3`。
