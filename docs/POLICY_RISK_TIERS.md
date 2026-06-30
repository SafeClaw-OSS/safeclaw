# Policy 风险分级层 (Risk Tiers) — 参考

> 状态:**引擎 + Gmail 表已实现并测试通过 (safeclaw v1.0.27)**。前端 console policy UI、
> 审批页消费(approval-record 盖 effective risk)、`service-intents.ts` 移植 = 下一轮(纯前端)。
> 日期:2026-06-30。源码即权威:`src/core/policy.rs`(类型+解析)、`src/storage/plaintext.rs`
> (`VaultAux.policy`)。关联 `docs/PROTOCOL.md §6`、`docs/STORES_AND_ITEMS.md §7`。

## 1. 背景:为什么要这一层

读一封 Gmail 邮件曾要 **两次** passkey 审批——一次 `GET …/messages`(列 id),一次
`GET …/messages/{id}`(读正文)。两个动作各自一条 rule、各自手填默认值,没有"按风险批量
调整"的抓手。

本质:**系统必然要给每个新动作一个默认 policy**。逐动作分类是绕不开的——区别只在于这个分类
**有没有名字、能不能批量改**。给它一个名字(`low`/`medium`/`high`/`critical`)= 出厂即合理
+ 一键全局调整。

---

## 2. 两套词汇 — 永不在同一对象上共存

这是这一版的核心修正。**risk 是分类,level 是决定**,它们分属不同的字段、不同的对象:

| 词汇 | 类型 | 取值 | 出现在哪 |
|---|---|---|---|
| **risk**(风险分级) | `RiskTier` | `low \| medium \| high \| critical`(标准严重度) | **只在 rule 上**(`[[rule]] risk = …`) |
| **level**(访问决定) | `AccessLevel` | `allow \| ask \| ask-always \| deny` | 只在 risk 映射表、读写 default floor、解析输出 |

- **rule 只声明 risk,不带 level。**(杀掉了旧版 level/risk 二义性——旧版一条 rule 既能标 risk
  又能钉 `level`,谁赢说不清。)
- **level 永远不挂在 rule 上。** 它是 risk 经 `risk` 映射表算出来的*结果*,或是 default floor
  的*决定*。

两套词汇的桥梁是 `risk` 映射表(§3)。risk 挂在 **rule**(matcher + 可选 `body` 谓词)上,不是
固定的 action 枚举——未来 `amount > $100` 这类带参谓词 rule 同样挂 risk,不留天花板。

### `AccessLevel` 语义

| level | 行为 |
|---|---|
| `allow` | 直接放行,不审批 |
| `ask` | 审批一次,之后在该 rule 的 `ttl` 内复用 |
| `ask-always` | 每次都审批,永不缓存 |
| `deny` | 无条件拒绝 |

---

## 3. risk → level 映射表(`aux.policy.risk`)

risk 和 level 之间**唯一**的旋钮。稀疏 + 自带默认 + 用户可改 + 现读(realtime):

```
默认:  low → allow,  medium → ask,  high → ask-always,  critical → ask-always
```

- **稀疏**:每个 tier 可选。用户只改一个 tier(`{"medium":"allow"}`)是干净的
  JSON-merge-patch,未设的 tier 走内建默认。
- **默认永不产出 `deny`**。**SafeClaw 是 gate,默认从不 block**——`critical` 默认也是
  `ask-always`,不是 `deny`。`deny` 是**主动选入**的:用户把 `critical` 设成 `deny`(全局),
  或把某一条 rule 重分类到一个映射为 deny 的 tier(单条)。
- **现读 → realtime**:映射表 sealed 在 `aux.policy.risk`,evaluator 每请求现读并即时映射。
  改完**下一个请求即生效,零缓存失效**,且**同 tier 的所有 rule 一起重新调音**。

```rust
// src/core/policy.rs
pub struct RiskMap { pub low/medium/high/critical: Option<AccessLevel> }
// RiskMap::get(tier) 填内建默认;参见 risk_map_default_never_denies 单测
```

---

## 4. 解析顺序(`PROTOCOL.md §6.4`)

对一个请求 `(method, path, body)`:

```
1. 规则层 — 在所有【匹配的】rule 里,有效 level 【最严格】者胜(deny-override / fail-safe)。
            平手时按 specificity(nginx 最长匹配)做 tiebreak,使 ask-cache scope 确定。
            匹配但无 risk(畸形)的 rule → 不决策,等同没匹配,继续往下。
2. 连接 default floor (aux.policy.connections.<id>.default 的 read/write)
3. 类别 default floor (aux.policy.categories.<cat>)
4. 全局 default floor (aux.policy.default)
5. 安全兜底 ask-always
```

> **冲突解析 = 最严格者胜(deny-override),不是最具体者胜。** 与 AWS IAM / Cedar 同款的
> fail-safe:两条 rule 同时命中,`critical`(严)即便没 `low`(松)那条具体,也是 `critical` 赢。
> specificity 只做平手 tiebreak(见 `most_restrictive_matching_rule_wins` 单测)。

ask 审批缓存 key = `(connection, rule_id, method)`,TTL = 命中 rule 的 `ttl`。

---

## 5. 封存 schema — 一棵 `aux.policy` 树

旧的 `aux.policy_defaults` + `aux.service_state` 二分**被替换为一棵** `aux.policy`
(`src/storage/plaintext.rs` `VaultAux.policy: Option<Policy>`;fresh vault 为 `None` →
daemon 用 `Policy::default()`):

```jsonc
"aux": {
  "policy": {
    "timeout": 300,                          // 审批 hold 秒数
    "risk": { "medium": "allow" },           // risk→level,稀疏自默认(§3)
    "default":    { "read": "allow", "write": "allow" },   // 全局读写 floor(level)
    "categories": { "llm": { "read": "allow", "write": "allow" } },  // 类别 floor
    "connections": {                         // 按 connection_id,不是按 service
      "gmail-work": {
        "default": { "read": "ask" },        // 覆盖该连接的读写 floor
        "rules": {                           // 稀疏的 per-rule 编辑/新增
          "read-email": { "risk": "low" },                      // 覆盖内建 rule
          "vip": { "match": "POST /…/messages/vip", "risk": "low" }  // 新增 rule
        }
      }
    }
  }
}
```

| 字段 | 含义 |
|---|---|
| `timeout` | 审批 hold 超时(秒) |
| `risk` | risk→level 映射(§3),稀疏自默认 |
| `default` | 全局读写 floor `Levels { read?, write?, ttl? }`——是**决定**(level),不是分类 |
| `categories.<cat>` | 类别 floor(`llm` / `channel` …),胜过 `default` |
| `connections.<connection_id>` | **每连接**用户 policy(`ConnectionPolicy { default?, rules }`) |

### 5.1 Per-connection,不是 per-service

用户 policy 按 **`connection_id`** 索引,不是按 service。一条连接的**内建 rule 集来自它所
实例化的那个 *service* recipe** 的 `policy.toml`;`connections.<id>.rules` 把用户编辑 merge
上去。一个 service 可有多条连接(`gmail`、`gmail-work`),各自独立的 policy 覆盖。
(连接模型见 `docs/CONNECTION_SCHEMA.md`。)

`RuleConfig`(稀疏)= `{ match?, label?, body?, risk?, ttl? }`,两种模式:

- **override**:id 命中某条内建 rule → 覆盖其 `risk`/`ttl`(及给出的 `label`/`body`);
- **add**:带 `match` 且 id 不在内建里 → 追加为一条新 rule(**有没有 `match` 决定是覆盖还是新增**)。

字段级 merge,用户 > recipe(见 `merge_rules` / `merge_levels` 单测)。

### 5.2 命名:`ttl`(不是 `ask_ttl`)

缓存 TTL 字段在**各处**统一叫 `ttl`(`PROTOCOL.md §6.1` 称 `policy.rules[].ttl`)。`Levels`
也有 `ttl`(floor 决定为 `ask` 时的缓存时长)。旧名 `ask_ttl` 已退役。

---

## 6. Recipe `policy.toml` 格式

`[default]` 块仍用 **level**(它是读写 floor 的*决定*);`[[rule]]` 块只用 **risk**:

```toml
# services/integration/gmail/policy.toml
[default]                              # floor 决定(level)——当没有 rule 命中时
read  = "ask"
write = "ask-always"

[[rule]]                              # 规则只分类(risk)
id    = "read-email"
label = "Read email content"
match = "GET /gmail/v1/users/me/messages/*"
risk  = "medium"
# 可选: body = "<regex>",  ttl = <秒>
```

`PolicyFileRule` 只解析 `risk`;**无 `risk` 的 rule 被静默跳过**(它永远无法决策)——
故 recipe 必有端到端测试守门(`compiled_gmail_policy_resolves_risk_tiers`)。

---

## 7. Gmail 默认表(已落地 `services/integration/gmail/policy.toml`)

| Action | match | risk | → 默认有效 level |
|---|---|---|---|
| List emails | `GET …/messages` | `low` | allow |
| List labels | `GET …/labels` | `low` | allow |
| Read email | `GET …/messages/*` | `medium` | ask(TTL 内复用) |
| Send email | `POST …/messages/send` | `high` | ask-always |
| Modify labels/archive/trash | `POST …/messages/*/modify` | `high` | ask-always |
| Delete email | `DELETE …/messages/*` | `critical` | ask-always(用户可改 `critical→deny` 则 deny) |

**对那次 2-次-审批的影响**:list = `low`→allow(自动放行),read = `medium`→ask(审批一次,
TTL 内连读不再 tap)。**两次批准变一次**。`delete` 标 `critical`——出厂是 `ask-always`(gate,
不 block);要彻底拒绝,用户把 `critical` 设成 `deny`(全局)或单独覆盖该 rule。

---

## 8. 兼容与影响

- **无迁移(pre-launch)**:`aux.policy` 是全新的合并树,替换旧 `policy_defaults` + `service_state`。
  **wipe + re-enroll**,无 dual-read,无 compat 层。`PLAINTEXT_VERSION` 仍为 3。
- **版本**:daemon `Cargo.toml` bump 到 **v1.0.27**,前端经 `health.version` 做兼容门。
- **退役**:rule 上的 `level` pin、`ask_ttl`、per-service 的 `service_state`、"default deny"。

---

## 9. 下一步(单独,需先与用户确认 —「前后端」)

1. 前端 console policy UI:rule 列表加「风险」列(常驻);`risk` 映射表编辑放 advanced;
   per-connection 覆盖编辑。
2. 审批页 SSoT:daemon 每请求把**有效 risk** 盖在 approval record;审批页读它(退役硬编码表);
   移植 `service-intents.ts` 的 per-service body 定制展示。
3. (未来)谓词引擎:`amount > X`、白名单等带参 matcher,risk 同样挂其上。
