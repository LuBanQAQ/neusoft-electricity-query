# 东软电费查询（单文件 适配青龙通知）

用于查询东软电费信息，支持**青龙环境变量配置**、**多账号**、**会话复用**、**低电量提醒**、**每周用电统计**等功能。

---

## 功能特性

* ✅ 支持 **多账号查询**（推荐）
* ✅ 支持 **单账号兼容模式**
* ✅ 支持 **会话缓存**（减少重复登录）
* ✅ 支持 **低电量阈值提醒**
* ✅ 支持 **仅变更时通知**
* ✅ 支持 **每周用电统计**
* ✅ 支持 **调试日志 / 原始 JSON 输出**

---

## 依赖

请确保运行环境已安装以下依赖：

* `requests`
* `gmssl`

---

## 青龙使用说明

脚本头示例：

```javascript
new Env("东软电费查询");
```

建议在青龙面板中通过**环境变量**进行配置。

---

## 环境变量配置（推荐）

### 1）多账号（优先推荐）

#### 变量名

* `DRJF_ACCOUNTS`

#### 格式（支持换行）

```text
用户名,密码,寝室号[,备注]
用户名2,密码2,寝室号2[,备注]
```

#### 说明

* 多账号也支持使用 `&` 分隔
* 单账号字段分隔符支持自动识别：

  * `,`
  * `@`
  * `#`

#### 示例（换行）

```text
DRJF_ACCOUNTS=2023xxxxxx,你的密码,7-A608,男寝A608
2022xxxxxx,你的密码,8-B302,女寝B302
```

#### 示例（`&` 分隔）

```text
DRJF_ACCOUNTS=2023xxxxxx,你的密码,7-A608,男寝A608&2022xxxxxx@你的密码@8-B302@女寝B302
```

---

### 2）单账号（兼容模式）

当你只需要查询一个账号时，可使用以下变量：

* `DRJF_USERNAME=xxx`
* `DRJF_PASSWORD=xxx`
* `DRJF_CUST_RECH_NO=7-A608`

#### 示例

```text
DRJF_USERNAME=2023xxxxxx
DRJF_PASSWORD=你的密码
DRJF_CUST_RECH_NO=7-A608
```

---

## 可选环境变量（高级配置）

### 基础配置

* `DRJF_CONFIG`：配置文件路径（JSON，可选，仍通过环境变量指定）
* `DRJF_SESSION_DIR`：会话目录（默认 `./drjf_sessions`）
* `DRJF_SESSION_FILE`：单账号模式指定会话文件（可选）
* `DRJF_TIMEOUT`：接口超时秒数（默认 `20`）
* `DRJF_LOGIN_TIMEOUT`：登录超时秒数（默认 `20`）

### 接口参数（一般无需修改）

* `DRJF_RECH_MER_MAP_ID`：默认 `326`
* `DRJF_MERCHANT_ID`：默认 `113377`（也可自动从会话提取）
* `DRJF_USER_INFO_ID`：可手动指定（通常无需）
* `DRJF_SESSIONTOKEN`：可手动指定（通常无需）

### 通知相关

* `DRJF_NOTIFY`：`1/0` 是否发送通知（默认 `1`）
* `DRJF_NOTIFY_ONLY_FAIL`：`1` 仅失败时通知（默认 `0`）
* `DRJF_LOW_THRESHOLD`：低电量阈值（数字，可选；低于则标记 `⚠️`）
* `DRJF_NOTIFY_ON_CHANGE`：`1` 仅数据变更 / 低阈值 / 周统计时通知（默认 `1`）

### 每周统计

* `DRJF_WEEKLY_STATS`：`1` 开启每周用电统计（默认 `1`）
* `DRJF_WEEKLY_NOTIFY_WEEKDAY`：每周统计通知日（`0=周一 .. 6=周日`，默认 `0`）

### 状态与调试

* `DRJF_STATE_DIR`：状态与历史目录（默认 `./drjf_state`）
* `DRJF_DEBUG`：`1` 输出调试日志
* `DRJF_RAW`：`1` 控制台打印成功项完整原始 JSON（默认 `0`）

---

## 配置优先级说明（建议）

推荐优先使用：

1. `DRJF_ACCOUNTS`（多账号）
2. 单账号变量（`DRJF_USERNAME` / `DRJF_PASSWORD` / `DRJF_CUST_RECH_NO`）

当 `DRJF_ACCOUNTS` 已配置时，通常优先按多账号模式处理。

---

## 目录说明（默认）

脚本会在运行目录下生成/使用以下目录（如未自定义）：

* `./drjf_sessions`：会话缓存目录
* `./drjf_state`：状态与历史记录目录

你可以通过以下变量自定义：

* `DRJF_SESSION_DIR`
* `DRJF_STATE_DIR`

---

## 常见建议

### 1）首次运行建议开启调试

```text
DRJF_DEBUG=1
```

### 2）需要排查接口返回内容时开启原始输出

```text
DRJF_RAW=1
```

### 3）只在有变化时通知（减少打扰）

```text
DRJF_NOTIFY_ON_CHANGE=1
```

### 4）设置低电量提醒阈值（示例）

```text
DRJF_LOW_THRESHOLD=20
```

---

## 示例：青龙环境变量（完整示例）

```text
DRJF_ACCOUNTS=2023xxxxxx,你的密码,7-A608,男寝A608
DRJF_NOTIFY=1
DRJF_NOTIFY_ONLY_FAIL=0
DRJF_NOTIFY_ON_CHANGE=1
DRJF_LOW_THRESHOLD=20
DRJF_WEEKLY_STATS=1
DRJF_WEEKLY_NOTIFY_WEEKDAY=0
DRJF_DEBUG=0
DRJF_RAW=0
```

---

## 注意事项

* 请妥善保管账号密码，避免泄露。
* 多账号配置时，建议添加备注，方便区分通知内容。
* 若接口参数（如 `MERCHANT_ID`）变更，优先使用默认自动提取；仅在异常情况下手动指定。
* 若登录或查询失败，可先开启 `DRJF_DEBUG=1` 和 `DRJF_RAW=1` 排查。

---

## License

仅供学习与个人使用，请遵守相关平台与学校规定。
