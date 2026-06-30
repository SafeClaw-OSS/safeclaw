# Policy 风险分级层 (Risk Tiers) — 设计草案

> 状态:**设计草案，待批准后实现引擎代码**。本文只定数据模型 (①) 与 Gmail 默认表 (②);
> Rust parser / 解析引擎 / 前端 UI 的改动列在 §6「实施步骤」,是批准本草案后的下一步。
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

### 2.3 安全靠"默认 + 警示",不靠"锁死"

用户**保留** action→risk 的管理权(哪怕默认折叠在 advanced)。安全护栏不是禁止用户改,而是:

- 作者出厂值是**保守基线**(宁可多问);用户不动 = 立刻可用且安全。
- 用户**下调**风险/放宽审批时 → 一次明确确认 + 标记「已偏离推荐值」。
- 用户**上调**风险/收紧审批 → 无摩擦。

---

## 3. 数据模型 (①)

贴着 main(v1.0.25)现有结构做**纯增量**扩展。涉及文件:`src/core/policy.rs`、
`src/storage/plaintext.rs`、`src/server/handlers/registry.rs`、`services/*/policy.toml`。

### 3.1 新增 `RiskTier` 枚举 — `src/core/policy.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}
```

### 3.2 `PolicyRule` 增加 `risk`,`level` 改为可选 — `src/core/policy.rs`

现状(`policy.rs:55`)`level` 是**必填**。改为:rule 二选一表达——要么 `risk`(走全局映射、可批量),
要么 `level`(钉死、escape hatch)。

```rust
pub struct PolicyRule {
    pub id: Option<String>,
    pub label: Option<String>,
    #[serde(default, rename = "match")]
    pub match_pattern: Option<String>,
    #[serde(default)]
    pub body: Option<String>,

    #[serde(default)]
    pub risk: Option<RiskTier>,        // 新增:作者的风险分类(走 risk_policy)
    #[serde(default)]
    pub level: Option<AccessLevel>,    // 改:必填 → 可选(显式钉死,优先于 risk)

    #[serde(default)]
    pub ask_ttl: Option<u64>,
}
```

> **兼容性**:`level` 从必填变可选是 serde 上的向后兼容变更——老的 `level = "..."` rule 原样工作。
> 不写迁移(与既往 wipe+re-enroll 一致)。约束:一条 rule 至少有 `risk` 或 `level` 之一;两者都缺 →
> 落到 service levels / defaults(沿用现有 fallback)。

### 3.3 全局 `risk_policy` 映射(用户可改)— `src/core/policy.rs` 的 `PolicyDefaults`

risk → level 的映射表,默认值即我们讨论的三档。挂在 `PolicyDefaults`(已 sealed 在 vault `aux`,
随 vault 走,用户可改;前端默认折叠在 advanced)。

```rust
pub struct PolicyDefaults {
    // ...现有 timeout / levels / type_levels 不变...
    #[serde(default)]
    pub risk_policy: Option<RiskPolicy>,   // 新增
}

pub struct RiskPolicy {
    pub low: AccessLevel,     // 默认 Allow
    pub medium: AccessLevel,  // 默认 Ask
    pub high: AccessLevel,    // 默认 AskAlways
}
// 内置默认:low=allow, medium=ask, high=ask-always
```

### 3.4 用户覆盖层增加 `risk` — `src/core/policy.rs` 的 `RuleOverride`

为兑现 §2.3 的"用户保留 action→risk 管理权",`RuleOverride` 既能钉死 `level`,也能改 `risk`:

```rust
pub struct RuleOverride {
    #[serde(default)]
    pub level: Option<AccessLevel>,  // 改:必填 → 可选(钉死最终 level)
    #[serde(default)]
    pub risk: Option<RiskTier>,      // 新增:重新分类该 rule 的风险
    #[serde(default)]
    pub ask_ttl: Option<u64>,
}
```

存储位置不变:`ServiceState.rule_overrides`(`plaintext.rs:78`,key = rule id),sealed in vault。

### 3.5 解析顺序(整合进现有引擎)

匹配到一条 rule 后,求它的**有效 level**,从高到低:

```
1. rule_override.level   (用户钉死)                      ← 最高
2. risk_policy[ rule_override.risk ]   (用户重分类 → 全局映射)
3. rule.level            (作者钉死 / 老 rule)
4. risk_policy[ rule.risk ]            (作者分类 → 全局映射)   ← 常规路径
5. (rule 无 risk 无 level) → 落到 service levels → type defaults → global defaults → AskAlways
```

rule **没匹配**时,完全沿用现有链路,无变化。`ask` 审批缓存 key 仍是 `(service, rule_id, method)`,不变。

**下调警示**:当 1/2 算出的有效 level **低于** 3/4(作者基线)时,前端在保存该 override 时弹一次确认
并打「已偏离推荐」标记。纯 UI/状态层,不影响引擎判定。

### 3.6 Registry 暴露 `risk` — `src/server/handlers/registry.rs`

`RegistryPolicyRule` 增加 `risk: Option<String>` 字段,让前端能渲染"风险列"并做按 risk 的批量操作。
`level` 同时保留(展示**有效** level,即解析后的结果),前端两列都显示。

---

## 4. Gmail 默认表 (②)

把 `services/integration/gmail/policy.toml` 改写为 risk 驱动。**注意:此文件与 §6 的 parser 改动
一起落地**——在 `level` 仍必填、parser 还不认 `risk` 之前提交会 break。这里给的是目标态。

```toml
# 全局默认(无匹配 rule 时):读=ask、写=ask-always,保持现状
[default]
read = "ask"
write = "ask-always"

# ── low:只读、无副作用、无隐私正文(列表/元数据)→ risk_policy.low=allow ──
[[rule]]
id = "list-emails"
label = "List emails"
match = "GET /gmail/v1/users/me/messages"
risk = "low"

[[rule]]
id = "list-labels"
label = "List labels"
match = "GET /gmail/v1/users/me/labels"
risk = "low"

# ── medium:读到隐私正文,但无外发/无破坏 → risk_policy.medium=ask(首次审批,TTL 内复用)──
[[rule]]
id = "read-email"
label = "Read email content"
match = "GET /gmail/v1/users/me/messages/*"
risk = "medium"

# ── high:外发 / 不可逆 → risk_policy.high=ask-always(每次审批)──
[[rule]]
id = "send-email"
label = "Send email"
match = "POST /gmail/v1/users/me/messages/send"
risk = "high"

[[rule]]
id = "modify-email"
label = "Modify labels / archive / trash"
match = "POST /gmail/v1/users/me/messages/*/modify"
risk = "high"

# ── 显式钉死的 escape hatch 示例:删除整体禁止,不走 risk 映射 ──
[[rule]]
id = "delete-email"
label = "Delete email"
match = "DELETE /gmail/v1/users/me/messages/*"
level = "deny"
```

**对开头那次 2-次-审批的影响**:`list-emails` = low → allow(自动放行),`read-email` = medium →
ask(审批一次,TTL 内连读多封不再 tap)。**两次批准变一次**,正是预期效果。

`modify-email` 是新增(`gmail.modify` scope 已在 service.toml),归 high。`delete-email` 保持现状
`deny`,顺带演示 §3.5 的「作者钉死 level、不走 risk」逃生通道。

---

## 5. 兼容与影响

- **无迁移**:`level` 必填→可选、`RuleOverride.level` 必填→可选,都是 serde 向后兼容;现存 vault 里
  老的 override(只有 `level`)原样工作。沿用 wipe+re-enroll 习惯,不写 migration。
- **行为不变项**:无匹配 rule 的 fallback 链、`ask` 审批缓存 key、domain allowlist——均不动。
- **版本**:协议层结构变更,按惯例 bump `Cargo.toml`(v1.0.25 → v1.0.26),前端经 `health.version` 做兼容门。

---

## 6. 实施步骤(批准本草案后的下一步,**尚未做**)

1. `src/core/policy.rs`:加 `RiskTier`、`RiskPolicy`;`PolicyRule.risk` + `level` 可选;
   `RuleOverride.risk` + `level` 可选;内置 `risk_policy` 默认表。
2. `src/core/policy.rs` 解析:在 `evaluate_policy_with_match` 里按 §3.5 求有效 level;
   补单元测试(low→allow / medium→ask / high→ask-always / override 重分类 / level 钉死优先)。
3. `src/storage/plaintext.rs`:`RuleOverride` 字段扩展(随 `ServiceState` 走,无 schema version 跳变,
   因为是字段级可选增量)。
4. `src/server/handlers/registry.rs`:`RegistryPolicyRule` 暴露 `risk` + 有效 `level`。
5. `services/integration/gmail/policy.toml`:落 §4 目标态(与 1-4 同一提交,避免 break)。
6. `Cargo.toml`:bump v1.0.26。
7. 前端(`safeclaw-pro-frontend` console policy UI):rule 列表加「风险」列(常驻);
   risk→policy 映射表 + 谓词编辑放 advanced;下调时弹确认 + 「偏离推荐」标记。
8. (未来,非本轮)谓词引擎:`amount > X`、白名单等带参 matcher,risk 同样挂其上。

> 范围属「前后端」(Rust core + console),按约定每一步动手前再与用户确认。本文是确认所依据的草案。
