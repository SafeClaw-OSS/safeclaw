# Policy — 审批策略 (per-action decisions)

> 状态:**已实现 (safeclaw v0.9.2)**。源码即权威:`src/core/policy.rs`(类型 + 求值)、
> `src/service/mod.rs`(recipe 解析)、`src/storage/plaintext.rs`(`VaultAux.policy`)。
> 关联 `design/protocol.md §6`、`design/stores-and-items.md §7`、`design/connection-schema.md`。

## 1. 设计:为什么没有 "risk level"

系统必然要给每个动作一个默认 policy。曾经有一版把动作先分类为 `low/medium/high/critical`
四档 **risk**,再经一张 per-vault 映射表派生到 **level**(决策)。这一层被删掉了,理由:

- **risk 是主观的**。GitHub/Google 自己都不给 endpoint 标 risk;由我们(recipe 作者)这个
  第三方去替它打分,是最弱的一种主观。主流做法(MCP tool annotations、HTTP safe/idempotent、
  Android/Google 的敏感度)要么标**客观行为事实**,要么由**资源拥有方**标——都不是第三方主观分数。
- **不驱动动作的标注就是噪音**。一个只挂在 UI 上、不改变默认决策的 risk 徽章,只会误导。
- 用户的心智模型是 **动作 → 决策**("删库,allow 还是 ask?"),risk 在中间插了一层用户没
  授权的间接。

结论:**单一词汇 `level`(访问决策)**。recipe 作者直接在动作上写决策;用户 per-connection
覆盖。基线由**请求方法**客观派生(读/写)。

## 2. 唯一词汇:`AccessLevel`

`level` 既是 rule 声明的东西,也是 read/write floor 声明的东西,也是求值输出。

| level | 行为 |
|---|---|
| `allow` | 直接放行,不审批 |
| `ask` | 审批一次,之后在该 rule 的 `ttl` 内复用 |
| `ask-always` | 每次都审批,永不缓存 |
| `deny` | 无条件拒绝 |

**deny 从不做出厂默认**:SafeClaw 是 gate 非 block。recipe/用户显式把某条 rule 设成 `deny`
才会拒。

## 3. Recipe `policy.toml` 格式

`[default]` 是读写 floor(未命中任何 rule 时);`[[rule]]` 每条直接声明 `level`:

```toml
# services/integration/gmail/policy.toml
[default]                              # 读/写 floor(level)
read  = "ask"
write = "ask-always"

[[rule]]
id    = "read-email"
label = "Read email content"
match = "GET /gmail/v1/users/me/messages/*"
level = "ask"
# 可选: body = "<regex>",  ttl = <秒>
```

`match` = `"METHOD /path"` 或 `"/path"`(任意方法);`*` 匹配一个 path segment。
**无 `level` 的 rule 被静默跳过**(它永远无法决策)。

## 4. 解析顺序(`design/protocol.md §6.4`)

对一个请求 `(method, path, body)`:

```
1. 规则层 — 在所有【匹配的】rule 里,【最严格】的 level 胜(deny-override / fail-safe)。
            平手按 specificity(nginx 最长匹配)tiebreak,使 ask-cache scope 确定。
            匹配但无 level 的 rule → 跳过。
2. 连接 default floor   (aux.policy.connections.<id>.default 的 read/write)
3. 类别 default floor   (aux.policy.categories.<cat>)
4. 全局 default floor   (aux.policy.default)
5. 安全兜底 ask-always
```

- **冲突解析 = 最严格者胜(deny-override)**,不是最具体者胜。与 AWS IAM / Cedar 同款 fail-safe。
  Restrictiveness 全序:`deny > ask-always > ask > allow`。
- **method 派生基线**:floor 用 `is_write_method`(`POST|PUT|PATCH|DELETE` → `write`,否则
  `read`)在读/写之间取一个 level。这是"从协议事实推默认",零主观。
- ask 审批缓存 key = `(connection, rule_id, method)`,TTL = 命中 rule 的 `ttl`。

## 5. 封存 schema — 一棵 `aux.policy` 树

`src/storage/plaintext.rs` `VaultAux.policy: Option<Policy>`;fresh vault 为 `None` →
daemon 用 `Policy::default()`(allow-everywhere floor + `llm`/`channel` 类别 allow)。

```jsonc
"aux": {
  "policy": {
    "timeout": 300,                                      // 审批 hold 秒数
    "default":    { "read": "allow", "write": "allow" }, // 全局读写 floor(level)
    "categories": { "llm": { "read": "allow", "write": "allow" } },
    "connections": {                                     // 按 connection_id,不是按 service
      "gmail-work": {
        "default": { "read": "ask" },                    // 覆盖该连接的读写 floor
        "rules": {                                       // 稀疏的 per-rule 编辑/新增
          "read-email": { "level": "allow" },                       // 覆盖内建 rule 的决策
          "vip": { "match": "POST /…/messages/vip", "level": "allow" } // 新增 rule
        }
      }
    }
  }
}
```

`RuleConfig`(稀疏)= `{ match?, label?, body?, level?, ttl? }`,两种模式:
- **override**:id 命中内建 rule → 覆盖其 `level`/`ttl`(及给出的 `label`/`body`);
- **add**:带 `match` 且 id 不在内建里 → 追加新 rule(有没有 `match` 决定是覆盖还是新增)。

字段级 merge,用户 > recipe(见 `merge_rules` / `merge_levels` 单测)。

### 5.1 Per-connection,不是 per-service

用户 policy 按 **`connection_id`** 索引。一条连接的内建 rule 集来自它所实例化的那个 *service*
recipe 的 `policy.toml`;`connections.<id>.rules` merge 上去。一个 service 可有多条连接
(`gmail`、`gmail-work`),各自独立覆盖。

## 6. 兼容与影响

- **无迁移(pre-launch)**:`aux.policy` 树的 `risk` 字段被删除;旧存储里若有该字段,反序列化
  时忽略(sparse + `#[serde(default)]`)。wipe + re-enroll 亦可。`PLAINTEXT_VERSION` 仍为 3。
- **版本**:daemon `Cargo.toml` bump 到 **v0.9.2**;前端经 `health.version` 做兼容门。
- **退役**:`RiskTier` / `RiskMap` 类型、`aux.policy.risk` 映射表、recipe `[[rule]]` 的
  `risk=` 字段、console 的 "Risk levels" 全局旋钮。recipe 里 `risk="X"` 已按
  `low→allow / medium→ask / high|critical→ask-always` 就地换成 `level`(行为保持)。
