# Policy 风险分级层 (Risk Tiers)

> 状态:**引擎 + Gmail 表已实现并测试通过 (safeclaw v1.0.26)**。前端 console UI、审批页消费
> (approval-record 盖 risk)、service-intents 定制展示移植 = 下一轮。
> 日期:2026-06-30。关联 `safeclaw-pro-backend/docs/POLICY.md`(术语与三层 fallback 的源头)。

## 1. 背景:为什么要这一层

现状:读一封 Gmail 邮件要 **两次** passkey 审批——一次 `GET /messages`(列 id),一次
`GET /messages/{id}`(读正文)。两个动作各自一条 rule、各自标 `level`,默认值是逐 rule 手填的,
没有"按风险批量调整"的抓手。

问题的本质:**系统必然要给每个新出现的动作一个默认 policy**。如果默认全是 `ask`,用户就被审批淹没。
所以一定有人逐动作分类——区别只在于这个分类**有没有名字、能不能批量改**。给它名字(low/medium/high)
= 出厂即合理 + 一键全局调整;不给名字 = 现状(每条 rule 各自为政,无法批量)。后者严格更弱。

## 2. 核心决策

### 2.1 选 A(风险分级),不选 B(逐 rule 直配)

- **A**:`rule → risk → policy`。risk 由 recipe 作者出厂分类,全局 `risk_policy` 把 risk 映射成 `level`。
  零配置即拿到合理默认;用户可一键"所有 low 自动放行"。
- **B**:`rule → policy` 直配。等价于把 A 的 risk 藏起来且不让批量——更少的能力,没换来真正的简单。

### 2.2 risk 挂在 **rule** 上,不是固定的 action 枚举

这是关键的可扩展性决策。一条 rule = **matcher(+ 可选谓词)**。action 路径匹配(`POST /messages/send`)
只是最粗的一种 rule。未来 payment 等场景需要带参数的谓词 rule(`amount > $100`、`merchant ∉ 白名单`),
风险等级要能挂在这些 rule 上,而不是被钉死在一张固定的"动作清单"里。

> 现有 `PolicyRule` 已经有 `body`(正则匹配请求体)字段——谓词 rule 的雏形已在。risk 挂 rule,
> 谓词引擎成熟时天然适配,不留天花板。

### 2.3 安全靠"保守默认 + 主动修改",不靠"锁死"

用户**保留** action→risk 的管理权(`RuleOverride.risk`,前端可折叠在 advanced)。安全护栏:

- 作者出厂值是**保守基线**(宁可多问);用户不动 = 立刻可用且安全。
- 用户要放宽,必须**主动**改 `risk_policy`(全局)或某条 rule 的 override(单条)。
- "下调时弹确认 / 标记偏离推荐"是**可选的前端提示**,不进引擎(引擎只算 level、不懂"基线 vs 偏离")。
  本轮不做,后续做也是纯 UI。

---

## 3. 数据模型与解析(已实现)

贴着现有结构做**纯增量**扩展。改动文件:`src/core/policy.rs`(主)、`src/state.rs`、
`src/service/mod.rs`、`src/server/handlers/registry.rs`、`services/integration/gmail/policy.toml`、
`Cargo.toml`。`src/storage/plaintext.rs` 的 `ServiceState`/`RuleOverride` 是类型引用,字段级可选增量,
**无 schema version 跳变、无迁移**。

### 3.1 `RiskTier` + `RiskPolicy` — `src/core/policy.rs`

```rust
#[serde(rename_all = "kebab-case")]
pub enum RiskTier { Low, Medium, High }   // + Display + RiskTier::parse(&str)

pub struct RiskPolicy { pub low: AccessLevel, pub medium: AccessLevel, pub high: AccessLevel }
// Default: low=Allow, medium=Ask, high=AskAlways；RiskPolicy::get(tier) -> AccessLevel
```

### 3.2 `PolicyRule`:加 `risk`,`level` 改可选 + `effective_level()`

`level` 由必填改可选。rule 二选一表达——`risk`(走全局映射、可批量)或 `level`(钉死、escape hatch)。
解析逻辑收进一个纯方法:

```rust
pub struct PolicyRule { /* …id/label/match/body… */
    #[serde(default)] pub risk: Option<RiskTier>,
    #[serde(default)] pub level: Option<AccessLevel>,   // 必填 → 可选
    #[serde(default)] pub ask_ttl: Option<u64>,
}

impl PolicyRule {
    // 显式 level(钉死) > risk_policy[risk](可调) > None(都没有 → 调用方穿透)
    pub fn effective_level(&self, risk_policy: Option<&RiskPolicy>) -> Option<AccessLevel> {
        self.level.clone()
            .or_else(|| self.risk.and_then(|r| risk_policy.map(|rp| rp.get(r))))
    }
}
```

### 3.3 `risk_policy` 挂在 `PolicyDefaults`(用户可改,realtime)

```rust
pub struct PolicyDefaults { /* timeout / levels / type_levels 不变 */
    #[serde(default)] pub risk_policy: Option<RiskPolicy>,   // None → RiskPolicy::default()
}
```

放这里有两个好处:① 它本就 sealed 在 vault `aux.policy_defaults`,**自动复用现有
`GET/POST /vault/policy` 端点**读写,不新增 API、不迁移;② `evaluate_request_policy` 每个请求
**现读** `policy_defaults` 并 layer 到默认值上(`src/state.rs`,与 type_levels 同一处)——所以
改 `risk_policy` 后**下一个请求即生效,零缓存失效**。

### 3.4 `RuleOverride`:加 `risk`,`level` 改可选

```rust
pub struct RuleOverride {
    #[serde(default)] pub level: Option<AccessLevel>,  // 必填 → 可选(钉死)
    #[serde(default)] pub risk:  Option<RiskTier>,     // 新增(重分类该 rule)
    #[serde(default)] pub ask_ttl: Option<u64>,
}
```

### 3.5 解析在**评估时**完成,不在合并时(关键修正)

引擎是两段式:`bootstrap_cache_from_view`(unlock 和**每次在线写 policy** 后都跑)建 cache;
`evaluate_request_policy` 每请求评估。risk→level 的解析放在**评估**,因为只有这样改 `risk_policy`
才零失效地 realtime(同 §3.3)。两步配合实现完整优先级:

**合并时**(`merge_rule_overrides`)把 override 的意图折进 rule 的 `(level, risk)` 对:
- `override.level` 在 → 钉死(保留作者 risk 仅供显示,但 `effective_level` 里 level 胜);
- 否则 `override.risk` 在 → 重分类:**清掉**作者 `level`(否则作者钉死的 level 会盖过用户的 risk),`risk=override.risk`;
- 都没有 → 原样(仅 `ask_ttl` 取并)。

**评估时**(`evaluate_policy_with_match`)对匹配中的 rule 调 `effective_level(defaults.risk_policy)`:

```
1. rule.level(已含 override.level 钉死)                     ← 最高
2. risk_policy[ rule.risk ](已含 override.risk 重分类)       ← 常规
3. 都为 None → 该 rule 不决策,穿透到 service levels → type → global → AskAlways
```

> 第 3 条是对早期草案的修正:**不**为"既无 risk 又无 level"的 rule 发明一个 AskAlways 兜底——
> 现有默认链已经回答"没有具体决定"。匹配中但 `effective_level` 为 `None` = 继续往下走,等同没匹配。

rule **没匹配**、`ask` 审批缓存 key `(service, rule_id, method)`、domain allowlist——全不变。

### 3.6 Registry 暴露 `risk` + 有效 `level` — `registry.rs`

`RegistryPolicyRule` 加 `risk: Option<String>`;`level` 改 `Option<String>` 且为**有效 level**
(显式 pin,否则按 risk 经**默认** `risk_policy` 映射)。

> **SSoT / realtime**:registry 给的是**基线**(默认 risk_policy),够 agent 看个大概、够 policy UI
> 渲染(UI 自己读用户的 `risk_policy` 重算有效值)。**真正生效的有效 risk/level 由 daemon 每请求现算**,
> 下一轮**盖在 approval record 上**给审批页读——审批页因此不读任何静态表,realtime by construction。
> 这退役了 frontend `service-intents.ts` 里那张硬编码 risk 表(其 per-service body 展示逻辑保留/移植)。

---

## 4. Gmail 默认表(已落地 `services/integration/gmail/policy.toml`)

| Action | match | risk | → 有效 level |
|---|---|---|---|
| List emails | `GET …/messages` | low | allow |
| List labels | `GET …/labels` | low | allow |
| Read email | `GET …/messages/*` | medium | ask(TTL 内复用) |
| Send email | `POST …/messages/send` | high | ask-always |
| Modify labels/archive/trash | `POST …/messages/*/modify` | high | ask-always |
| Delete email | `DELETE …/messages/*` | — (钉死 `level=deny`) | deny |

**对那次 2-次-审批的影响**:list = low→allow(自动放行),read = medium→ask(审批一次,TTL 内连读不再 tap)。
**两次批准变一次**。`modify-email` 为新增(`gmail.modify` scope 已在 service.toml);`delete-email`
保持 `deny`,演示「作者钉死 level、不走 risk」的逃生通道。

`src/service/mod.rs::compiled_gmail_policy_resolves_risk_tiers` 端到端验证这张表真的解析+解析到位
(loader 对解析失败的 policy 是**静默丢弃**,故必须有此测试守门)。

---

## 5. 兼容与影响

- **无迁移**:`PolicyRule.level`、`RuleOverride.level` 必填→可选都是 serde 向后兼容;现存 vault 里
  只含 `level` 的老 override 原样工作。`PLAINTEXT_VERSION` 不变。
- **行为不变项**:无匹配 rule 的 fallback 链、`ask` 审批缓存 key、domain allowlist、`default_read_level`
  的预加载启发式(只看 service `[default] read`,不看 per-rule)——均不动。Gmail `list` 改前改后有效
  level 都是 `allow`,预加载行为不变。
- **版本**:bump `Cargo.toml` v1.0.25 → **v1.0.26**,前端经 `health.version` 做兼容门。
- **测试**:`cargo test` 全绿(220 passed),含新增 risk 解析 / override 重分类 / level 钉死 / 穿透 /
  无-risk_policy 降级 / Gmail 端到端。

---

## 6. 状态与下一步

**本轮已做(v1.0.26,在 worktree,待 review 后 merge main):**
1. ✅ `policy.rs`:`RiskTier`/`RiskPolicy`/`effective_level`;`PolicyRule`/`RuleOverride` 加 risk + level 可选;`merge_rule_overrides` 优先级;`PolicyDefaults.risk_policy` + 默认表 + 单测。
2. ✅ `state.rs`:评估时 layer 用户 `risk_policy`(realtime)。
3. ✅ `service/mod.rs`:`PolicyFileRule` 解析 risk;`to_policy_rules` 跳过既无 risk 又无 level 的 rule;Gmail 端到端测试。
4. ✅ `registry.rs`:`RegistryPolicyRule` 暴露 risk + 有效 level。
5. ✅ `services/integration/gmail/policy.toml`:risk 化。
6. ✅ `Cargo.toml` v1.0.26。

**下一轮(单独,需先与用户确认 —「前后端」):**
7. 前端 `safeclaw-pro-frontend` console policy UI:rule 列表加「风险」列(常驻);`risk_policy`
   映射表编辑放 advanced。
8. 审批页 SSoT:daemon 每请求把**有效 risk** 盖在 approval record;审批页读它(退役硬编码表);
   移植 `service-intents.ts` 的 per-service body 定制展示并扩到更多服务。
9. (未来)谓词引擎:`amount > X`、白名单等带参 matcher,risk 同样挂其上。

> 范围属「前后端」(Rust core + console),每一步动手前与用户确认。
