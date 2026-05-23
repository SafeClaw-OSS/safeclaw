# SafeClaw Protocol — SUDP Concrete Profile

> **Doc state (2026-05-23)**: §4.0 + §4.1 endpoint table 和 §4.7 vault selection 已同步到 v1 design。§4.3 (`/challenge`)、§4.4 (`/grant`)、§4.5 (broker)、§4.6 + §4.6.1 (`safeclaw-vault` virtual service)、§6.2 (`/state/*`)、§8 sequences 仍引用 legacy endpoint 名，**待统一**。冲突时以 §4.0/§4.1 为准。
>
> **2026-05-23 update**: §4.1 endpoint table 补上 `GET /c/registry`（service catalog，含 `sub` field）；`POST /v/{vid}/use/{service}` 与 `POST /v/{vid}/use/{service}/{rest}` 两种 form（catch-all service 走前者）。`/c/registry` 把 service.toml 的 `name + sub` 暴露给前端，approve UI 用它显示 "Inbox (demo target)" 而不是 raw id。
>
> 本文是 SafeClaw daemon 实现的 cryptographic protocol 规约。它是 **SUDP paper** 的一个 **concrete profile**：固定算法选择、wire format、endpoint 映射、domain-separation labels 等。
>
> **不重复 SUDP paper 的内容**（key hierarchy 推导、phase 形式化、安全证明等），仅在需要锚定时 cross-reference。
>
> **配套文档**：
> - SUDP paper: `safeclaw-paper-nips/sections/{main,appendix}/0[3-9]-*.tex`（canonical 抽象协议）
> - System design + SUDP-aligned 决策: `../SAFECLAW_V1_DESIGN_HANDOFF.md`
> - CLI architecture: `../CLI_DESIGN_HANDOFF.md`
> - Service TOML schema: `./SERVICES.md`（不同文档，service 协议层）

---

## 1. SUDP Roles → SafeClaw 实例化

| SUDP role | SafeClaw 实例 |
|---|---|
| **U** Authorizer | 用户本人，通过 WebAuthn passkey + browser |
| **R** Requester | LLM agent，通过 `POST /v/{vid}/use/<svc>/<rest>` 发起 op |
| **T** Custodian | safeclaw daemon |
| **E** Environment | 上游 service (OpenAI/Anthropic/...)，非 SUDP 参与者 |
| **`\Sigma`** Sealed state | `~/.safeclaw/vault.dat`（SCSV format，§5.1） |
| **`\mathcal{A}`** Tamper-resistant module | FIDO2 authenticator (Touch ID/YubiKey/...) |
| **U→T authenticated confidential channel** | TLS（外层）+ HPKE envelope（应用层端到端，§4.2）|

`U→T 通道` 用 **TLS + HPKE envelope 双层**：TLS 防外部 wire 窃听者；HPKE envelope 防中介节点（Pro relay、L7 proxy、TLS-terminating LB）— 后者是 SUDP §03 confidentiality requirement 的实现机制。详见 §4.2。

SUDP paper §05-sudp-protocol/00-roles-patterns.tex 是上述映射的形式定义来源。

---

## 2. Concrete Primitive Choices

按 SUDP paper §05-sudp-protocol/03-abstract-primitives.tex 的 abstract primitive interface，本 profile 选择：

| Primitive | Algorithm | 备注 |
|---|---|---|
| `H` collision-resistant hash | SHA-256 | — |
| `KDF` extract-then-expand | HKDF-SHA-256 | RFC 5869 |
| `(Enc, Dec)` AEAD | XChaCha20-Poly1305 | 192-bit nonce, AAD-protected |
| `(Sig, Vrfy)` signing | ECDSA-P-256 over SHA-256 | WebAuthn standard, EUF-CMA |
| `(Encap, Decap)` KEM (export delivery) | ECDH-P-256 + HKDF-SHA-256 | 用于 export response sealing，详 §4.5 |
| HPKE (outer envelope) | DHKEM(X25519, HKDF-SHA-256) + HKDF-SHA-256 + ChaCha20-Poly1305 | RFC 9180 single-shot 模式，详 §4.2 |
| `(Wrap, Unwrap)` key wrap | XChaCha20-Poly1305-as-wrap | AAD = `DS_wrap ‖ ver ‖ cid_c` |
| `CSPRNG` | OS source (`OsRng`) | — |
| Canonical serialization | RFC 8785 JCS subset | 详 §3.3 |

### 2.1 Domain-separation labels

所有 KDF info / AEAD AAD prefix 用以下 labels（前缀 `safeclaw/v1/`，每个标签互不重叠）：

| Label | 用途 |
|---|---|
| `safeclaw/v1/userkey\0` | userKey HKDF info |
| `safeclaw/v1/kek\0` | KEK derivation info |
| `safeclaw/v1/wrap\0` | Wrap AAD prefix |
| `safeclaw/v1/state\0` | Vault body AEAD AAD prefix |
| `safeclaw/v1/binding` | Channel binding β domain (`DS_bind`) — 标准 op |
| `safeclaw/v1/binding-setup` | Channel binding β domain — setup op |
| `safeclaw/v1/binding-identity` | Channel binding β domain — enroll/revoke op |
| `safeclaw/v1/binding-offline` | Channel binding β domain — offline handshake |
| `safeclaw/v1/deliver\0` | Export delivery KDF info (`DS_deliver`) |
| `safeclaw/v1/deliver-ad\0` | Export delivery AEAD AAD (`DS_deliver-ad`) |
| `safeclaw/v1/envelope\0` | HPKE outer envelope `info` 参数 |

### 2.2 Key hierarchy 引用

完整 key hierarchy 见 SUDP paper §05-sudp-protocol/01-protected-state.tex (`fig:hierarchy`)。本 profile 的具体实例化：

```
authenticator A (FIDO2 hmac-secret)
   │  PRF_c(η_c)                                            (browser/CLI side)
   ▼
y_c (raw PRF output, 32B, 仅 client 内存)
   │  HKDF-SHA-256(y_c; salt = η_c, info = DS_wrap ‖ cid_c ‖ ver)
   ▼
W_c (wrapping key, 32B)                                     (= "userKey" 在 code 里)
   │  per-credential，每写轮换
   │  跨 U → T 通道传输（详 §4.2 channel binding）
   ▼
K (state key, 32B, fresh per write)                         (= "DEK" 在 code 里)
   │  XChaCha20-Poly1305(K, fresh nonce, plaintext, AAD = DS_state ‖ ver ‖ nonce)
   ▼
M (vault plaintext)
```

`ver` 当前为 `0x0001`。

---

## 3. Operation Descriptor `o`

### 3.1 Structure

按 SUDP §05-sudp-protocol/02-authorized-operation.tex Definition 1（authorized operation）:

```json
o = {
  "act": {
    "type": "<setup|write|enroll|revoke|export>",
    "target": "<dotted path or special token>",
    "scope": { /* type-specific fields */ }
  },
  "bind": {
    "redeemer": "<T identifier, optional>",
    "recipient": "<base64 ECDH P-256 public key, only for type=export>"
  },
  "valid": {
    "expiry": <unix timestamp>
  }
}
```

### 3.2 Type 词汇表

ActType vocabulary 跟随 `sudp` 上游：`Enroll / Write / Rotate / Revoke / Export / Use / Custom`。

| `act.type` | SUDP phase | 说明 |
|---|---|---|
| `enroll` | Phase I + III.3 | 初始化 vault（首个 passkey）或注册新 passkey；vault 已存在时需要 `overwrite_proof.existing_assertion`（§3.5）|
| `write` | Phase III.3 | 写 M；每写自动轮换 K + acting credential 的 η_c |
| `revoke` | Phase III.3 | 删除一个 passkey |
| `rotate` | Phase III.3 | K 的轮换（v1 隐含在 write/enroll/revoke 中，不独立暴露） |
| `export` | Phase III.2 | 导出 M 子集；`o.bind.recipient` **必填**（sudp 2026-05-22 breaking change）|
| `use` | Phase III.1 | broker：T 取 secret 注入 R 的 upstream 调用，secret 不出 T |

**`reveal` 已废弃。** 历史的 "reveal = plaintext export to R" mode 已并入 `export` + "custodian-as-recipient" 部署模式：当 R 无 KEM 能力时，custodian 自己生成 ephemeral keypair、自己充当 recipient、execute_export → decap → 业务层用明文（如转给 agent over TLS）。custodian 显式承担"我把 secret 给出去了"的安全责任，paper 不打折，footgun 在 [[approve-ui-ownership-transfer]] UI 警告里显式化。

**Use op** 不再走 `proxy port :23295`（已废弃）；直接走 `POST /v/{vid}/use/<svc>/<rest>` R-side sugar（§4.1），内部 compile 成 Use op 后 redemption 阶段汇流到 `POST /op/{op_id}/approve`。

### 3.3 Type-specific `act.scope` schemas

| `act.type` | `act.target` | `act.scope` 必填字段 |
|---|---|---|
| `setup` | `"vault"` | `{ passkeys: [{cid, x, y, η_initial, user_key_initial, device_name, assertion}], initial_M: {...}, overwrite_proof?: {existing_cid, existing_assertion} }`<br>`overwrite_proof` 仅当 `vault.dat` 已存在时**必填**：旧 credential 对当前 grant 的 β 签名，证明授权摧毁旧 vault。详 §3.5。 |
| `write` | `"services.<name>"` 或 `"policy"` 或 `"preferences.<key>"` | `{ patch: {...} }` (JSON Merge Patch on `M[target]`) |
| `enroll` | `"passkeys"` | `{ new: { cid, x, y, η_initial, user_key_initial, device_name, assertion } }` |
| `revoke` | `"passkeys.<cid>"` | `{}` |
| `export` | M 内任意 dotted path（如 `"services.openai.api_key"`） | `{ recipient_epk: "<base64 P-256 pk>" }` |

### 3.4 Canonical serialization

`H(o)` presupposes deterministic encoding (per SUDP §05-sudp-protocol/03-abstract-primitives.tex)。本 profile 采用 **RFC 8785 JCS** 的 subset:
- UTF-8, sorted object keys
- Numbers: 不允许浮点（ints only）
- 不含 `null`, `undefined`
- 字符串: 标准 JSON escaping

实现见 `src/crypto/canonical.rs::canonicalize_body`。

`H(o)` = SHA-256 of JCS-encoded `o`（整个 act+bind+valid，不含外层 grant 字段）。

### 3.5 Setup overwrite (existing-credential proof)

当客户端发起 `type=setup` op 但目标位置已有 `vault.dat` 时，setup 等价于"摧毁旧 vault + 建新 vault"，需要双重授权：

1. **新 credential 的 grant signature**（即外层 grant `G` 的 `σ_c`，对当前 β 签名）— 授权"建立新 vault"
2. **旧 credential 的 existing-credential proof**（`o.act.scope.overwrite_proof.existing_assertion`，**也对当前 β 签名**）— 授权"摧毁旧 vault"

两个 assertion 都绑定**同一个 β = H(DS_bind ‖ r ‖ H(o))**，所以无法分离重放。

**Server 验证流程**（仅在 `vault.dat` 已存在时）:
1. 正常验证外层 grant（按 §4.4 步骤 1-6）
2. 加验：`overwrite_proof` 字段必须存在；`existing_cid` 在旧 `vault.dat` 的 dek_wrap entries 里；`existing_assertion` 用 `existing_cid` 对应的旧 passkey public key 验证 β 成功
3. 任一失败 → reject，不动 vault

**优雅性**: 不引入新 op 类型；复用 WebAuthn assertion primitive；β 自然 commit 双重授权；可拓展 N-of-M existing credentials approval（把 `existing_assertion` 改成 array 即可）。

### 3.6 `o.valid.expiry` 的派生

按本 profile 规定（详 SAFECLAW_V1_DESIGN_HANDOFF.md §5.2 + paper feedback list）：

> `o.valid.expiry := r.issued_at + freshness_ttl`

由 T 在 `GET /challenge` 时确定，client 不提议。Default `freshness_ttl = 300s`。

---

## 4. API Surface

### 4.0 URL conventions & vocabulary

**URL 分三组**：vault-scoped (`/v/{vid}/...`)、op-flat (`/op/{op_id}/...`)、custodian-level (`/c/...`)。Vault selection 永远走 URL path，不走 header；selection (URL) 与 authentication (Authorization header) 解耦。Custodian 不感知 user—`{vid}` 是 vault 标识符，principal→vault 的映射是部署层的事。

**Vault evolution guarantee.** SafeClaw 当前部署 `{vid}` = Supabase user UUID（1:1 user-to-vault）；将来扩展 multi-vault-per-user 时 URL shape 不变，只需在部署层加 principal→vaults lookup。

**Phase II.3 三动作 vocabulary.** U **authorizes** G（设备本地签）→ carrier **submits** G（网络传输；SafeClaw 用 Topology A，即 U-direct）→ T **redeems** G（验签 + execute）。Paper Phase II.3 形式上的 "Redemption" 严格指 T 端动作；submission 是 deployment 层动作，无独立 paper 动词。

### 4.1 Endpoint table

```
─── Vault-scoped (creation / management) ─────────────────────────────────────

POST  /v/{vid}/op                    R 创建 op            → { op_id, r, expires_at }    [HPKE: SHOULD]
POST  /v/{vid}/use/{service}         R-side sugar (Use, catch-all path = "*")           [HPKE: SHOULD]
POST  /v/{vid}/use/{service}/{rest}  R-side sugar (Use, sub-path under service root)    [HPKE: SHOULD]
POST  /v/{vid}/export/<key>          R-side sugar (Export)→ 同上                          [HPKE: SHOULD]
GET   /v/{vid}/passkeys              该 vault 的凭据列表
GET   /v/{vid}/events                tenant-scoped SSE 流

─── Op-flat (对已存在 op 的动作) ─────────────────────────────────────────────

GET   /op/{op_id}                    R: 轮询状态 / 结果 (unified poll + details)
POST  /op/{op_id}/approve            U: submit G → redeem → result                       [HPKE: MUST]
POST  /op/{op_id}/reject             U: 拒绝                                              [HPKE: MUST]

─── Custodian-level (无 vault 上下文) ────────────────────────────────────────

GET   /c/health
GET   /c/pubkey                      sc_pk (HPKE bootstrap)
GET   /c/registry                    service catalog: { id, name, sub?, description?,
                                     endpoints: [{ method, path, approval, wildcard? }] }
                                     —— 公开访问 (no auth)，frontend approve UI 用它把 service
                                     id 解析成 "Name (sub)" 展示
```

**`/v/{vid}/use/{service}` 两种 form 的边界**：services with `[[api]] path = "*"` 是 catch-all，agent 可以直接 POST 到 `/v/{vid}/use/{service}`（rest 为空），daemon 把 `path` 编入 op.scope 为 `/`；带 sub-path 的 service（如 OpenAI 的 `/v1/chat/completions`）走 `/v/{vid}/use/{service}/{rest}`。这两个 route 共享同一个内部 handler（`handle_no_rest` 是 thin wrapper），URL grammar 区分仅是 axum router 层面的事。

**`/c/registry` `sub` field**：v1 起 service.toml 的 `[service] sub` 通过 registry 暴露。前端不再在 UI 层 hardcode service 描述——`/approve/{op_id}` 收到 `use` op 时 fetch /c/registry 一次，按 `op.scope.service` 查 `name + sub`，渲染 "Inbox (demo target)"；找不到 fallback raw id。

**HPKE coverage.** 标注 `[HPKE: MUST]` 的 endpoint 请求体含 G 或同等密码学敏感物质，必须 HPKE 外信封封装（详 §4.2）。`[HPKE: SHOULD]` 的请求体含可观测意图（target 名、上游业务 payload），建议封装。无标注 = 无敏感载荷，TLS 足够。响应方向机密性由 SUDP Export sealing 在协议内部负责（§4.5）。

**R-side sugar 共用 SUDP-aware 内部实现.** `/v/{vid}/use/...`、`/v/{vid}/export/...` 的 handler 只做"URL+body → sudp::Operation"编译，编译完调同一个 op-creation service。**无 HTTP redirect，无平行实现。** Redemption 阶段统一 `POST /op/{op_id}/approve`。

**Creation 在 parent 下，存在物的动作 flat at root.** 任何 URL 中**最多出现一个 ID** — `/v/{vid}/...` 创建（vault 是 parent）、`/op/{op_id}/...` 操作 op（op_id 自带 vault 归属，daemon 内部 lookup）。杜绝 `/v/{vid}/op/{op_id}/...` 这种双 ID URL。

**Lifecycle ops live on `/v/{vid}/op`，不开独立 route.** Vault state 转换（unlock / lock）用 SUDP 的 `Custom(String)` 变体表达——`Custom("vault-unlock")` / `Custom("vault-lock")`——通过标准 `POST /v/{vid}/op` 创建、`POST /op/{op_id}/approve` 兑现。**没有** 专用 `/v/{vid}/unlock` / `/v/{vid}/lock` 路由。理由：SUDP 的 `Custom` 槽就是给 deployment 加生命周期 op 留的（详 sudp::ActType 文档），用它能继承 β / freshness / 凭据绑定的全部 grant machinery，又不污染 sudp 协议层。详 §6.3。

**Authentication.** 上面所有 endpoint 的 auth 由 `Authorization` header 承载（部署层任选：Supabase session / API key / mTLS / …）；selection 在 URL，authentication 在 header，正交。Custodian-level `/c/...` 无 vault 上下文，部分 endpoint（如 `/c/pubkey`）公开访问无 auth。

### 4.2 Outer envelope (HPKE)

**目的**: 让 U→T 的请求 confidentiality 端到端，不依赖 wire 上每一段 TLS 的 endpoint 都是 trusted。这覆盖 Pro relay、L7 proxy、TLS-terminating LB 这些会终结 TLS 看到 plaintext 的中介。详 §1 的 channel 注释。

**算法**（HPKE single-shot, RFC 9180）:
```
KEM  = DHKEM(X25519, HKDF-SHA-256)
KDF  = HKDF-SHA-256
AEAD = ChaCha20-Poly1305
```

**Wire format** (HPKE-wrapped POST request body):
```json
{ "envelope": "<base64( enc ‖ ct )>" }

  enc:  HPKE encapsulation (32B for X25519)
  ct:   HPKE ciphertext + Poly1305 tag (length = plaintext_length + 16)
```

**HPKE 参数**:
```
pkR    = sc_pk (server static public key, 详 §4.2.1)
info   = "safeclaw/v1/envelope\0"
aad    = method ‖ 0x00 ‖ path
        # method 是 ASCII uppercase, path 是 URL path
plaintext = JSON of inner request body (e.g., SUDP grant G for /grant)
```

**Server-side**: 用 sc_sk + 同样的 info/aad open，验证 AEAD tag 后得到 inner JSON，按 inner schema 处理。

**为什么 AAD 包含 method+path**:
- 把 envelope 绑死在特定 endpoint 调用
- 防止攻击者抓到一个 `/op/{op_id}/approve` envelope 重放到另一个 op_id 上
- AAD 失配 → AEAD tag verification fail → reject

**响应方向**:
- v1 outer envelope **仅作用于请求方向**（client → server）
- 响应方向有两类:
  - `type=export` 操作：响应已经用 recipient_epk ECDH 加密（详 §4.5），与 outer envelope 正交
  - 其他响应：仅含状态、metadata、不含 vault secret，不需要 envelope 加密
- 如果未来某 endpoint 响应需要 confidentiality，可以扩展（client 在 plaintext 里附 epk → server 用 §4.5 同样的 Encap/AEAD 加密响应）

#### 4.2.1 sc_pk / sc_sk lifecycle

`sc_pk` / `sc_sk` 是 daemon 的 **静态 X25519 keypair**，**仅** 用于 HPKE outer envelope；**不参与** KEK 派生或任何 SUDP key hierarchy（跟 v0.5.0 的 dual-role sk_d 不同）。

**生成时机**: daemon 首次启动（`safeclaw proxy start` 或 `safeclaw setup`）发现 `~/.safeclaw/crypto/sc_sk.jwk` 不存在 → 生成新 keypair → 持久化（atomic write）。

**rotation**: v1 不主动 rotation。Future work 可加 `safeclaw rotate-server-key` 命令。Rotation 时所有 client 需要重新 TOFU。详 §9.6。

**丢失 sc_sk 的影响**: vault 仍可用。Daemon 重启会生成新 sc_pk → 所有已 pinned client 第一次连看到 fingerprint mismatch 警告 → 用户手动重新 pin。Vault 数据不受影响（v0.5.0 sc_sk 是 KEK salt，丢就锁死；v1 sc_sk 角色单一）。

#### 4.2.2 Client 获取 sc_pk — 双路径

CLI 根据 daemon 的位置选择如何获取 sc_pk：

**路径 A（local mode）**: daemon 跟 CLI 在同一文件系统上（典型情况：用户笔记本上 daemon + CLI 同一台机器）
- CLI 直接读 `~/.safeclaw/crypto/sc_pk.jwk`（filesystem 已经认证）
- **不创建** `known_servers.json`，**不走 HTTP fetch**
- 这是默认场景，多数 OSS user 走这条路径

**路径 B（remote mode）**: daemon 在跨网位置（VPS、Pro relay、Docker 远端容器等）
- CLI 走 `GET /c/pubkey` 跨网 HTTP fetch
- TOFU pin 写到 `~/.safeclaw/known_servers.json`
- 后续连接对比 fingerprint：match → 用；mismatch → 警告（潜在 MITM 或 server keypair rotation）

**CLI 怎么知道走哪条路径**:
- CLI 子命令显式指定：`safeclaw <cmd>` 默认 local；`safeclaw --remote <name> <cmd>` 走 remote
- 远端配置在 `~/.safeclaw/config.toml` 的 `[remotes.<name>]` 段（host、port 等）
- 第一次 `safeclaw remote add <name> <url>` 触发 sc_pk fetch + 显示 fingerprint 让用户 OOB 验证 + 写 `known_servers.json`

`known_servers.json` schema（仅 remote mode 用户才有此文件）:
```json
{
  "<remote-name>": {
    "url": "https://...",
    "sc_pk_fingerprint": "<base64 H(sc_pk)>",
    "first_seen": "<ISO8601>",
    "last_used": "<ISO8601>"
  }
}
```

**为什么分双路径**:
- 多数 user 是 local mode，TOFU pin 是无意义的多余文件 + UX 摩擦
- Remote mode 才有 MITM 攻击面（中介节点替换 sc_pk）
- 跟 SSH 主流做法对齐：本机 socket 不用 known_hosts，跨网 ssh 才用

#### 4.2.3 实现位置

- Server: `src/crypto/envelope.rs`（重新启用，HPKE 实现，**不是** v0.5.0 的 ECIES 残留）
- Client (CLI): `src/cli/transport/hpke.rs` + `~/.safeclaw/known_servers.json` 管理
- Client (browser-side, embedded in CLI's passkey.html): `passkey.html` 里 JS HPKE 实现（可用 `@hpke/core` 之类 npm 库或写小段 wrapper）

### 4.3 `GET /challenge`

> Note: 此 endpoint 返回的全是 public material（`r`、cid、η_c），**不需要 HPKE envelope**。请求体也无（GET）。

**Request**: 无 body。

**Response** (200):
```json
{
  "r": "<base64 server_random, 32 bytes>",
  "expires_at": <unix timestamp, r.issued_at + freshness_ttl>,
  "credentials": [
    { "cid": "<base64url>", "η_c": "<base64 32B>" }
  ]
}
```

`credentials` 数组让 client 知道用哪个 passkey（提前选 cid 或让 OS 让用户选）+ 对应的 PRF salt η_c（用于 PRF eval）。

`r` 单次使用、TTL 5min（默认，可配）。详见 `src/passkey/challenge.rs`。

### 4.4 `POST /grant`

> **Naming note**: 这个 endpoint 之前叫 `/operation`，2026-05 改名为 `/grant`。HTTP body 装的就是 SUDP grant `G`；`o` 只是 grant 的内嵌字段。endpoint 名跟 body 类型对齐，更符合 paper 术语层级。`Operation` 在代码里仍是一等公民类型（`Grant.o: Operation`）。

**Request body** (SUDP grant `G = (o, r, cid_c, W_c, σ_c, opt)`)，**整体被 HPKE envelope 包裹**（详 §4.2）；下面是 HPKE 解密后的 inner JSON:
```json
{
  "o": { /* §3.1 */ },
  "r": "<base64 server_random>",
  "credential_id": "<base64url cid>",
  "user_key": "<base64 W_c, 32 bytes>",
  "user_key_next": "<base64 W_c^next, 32 bytes>",   // type=write/enroll/revoke 必填
  "prf_salt_next": "<base64 η_next, 32 bytes>",      // 与 user_key_next 配对
  "assertion": {
    "authenticator_data": "<base64>",
    "client_data_json":   "<base64>",
    "signature":          "<base64>"
  }
}
```

**Server validation**（按 SUDP §05-sudp-protocol/05-phase2-grant.tex II.3 的 6 步）:
1. 检查 `o.bind.redeemer` 等于 T_id（如指定）
2. 从 ChallengeStore consume `r`（不存在或已用 → reject）
3. 重算 `β' = SHA-256(DS_bind ‖ 0x00 ‖ r ‖ H(canonical(o)))`
4. 验 `Vrfy(pk_{cid_c}, β', σ_c)`，含 WebAuthn challenge re-binding：`clientDataJSON.challenge` 解码后应等于 `β'`
5. `Policy(cid_c, o)` admissibility（stateful，详 §5.4）
6. `o.valid.expiry > now()`

通过后按 `o.act.type` 派发：
- `setup` → `src/server/routes.rs::handle_setup` (Phase I)
- `write` → `src/server/routes.rs::handle_write` (Phase III.3)
- `enroll` → `handle_enroll`
- `revoke` → `handle_revoke`
- `export` → `handle_export`（详 §4.4）

**Response**:
- `setup/write/enroll/revoke`: `200` + `{ ok: true, ... }`（不含 secret）
- `export`: `200` + `π = { ct_d, delta }` (sealed for recipient_epk，详 §4.4)

### 4.5 Export sealing (Phase III.2)

按 SUDP §05-sudp-protocol/06-phase3-consumption.tex Phase III.2：

T 收到 `type=export` op 验证通过后:
```
s := M[o.act.target]
(K_d, ct_d) := Encap(o.bind.recipient_epk)             # ECDH-P-256
k_d := HKDF-SHA-256(K_d; ⊥, DS_deliver ‖ H(o))
delta := XChaCha20-Poly1305_Encrypt(k_d, fresh_nonce, s, AAD = DS_deliver-ad ‖ H(o))
π := { ct_d: <base64>, delta: <base64(nonce ‖ ct ‖ tag)> }
```

**Response**: `200 OK`, body = `π`。

**Client decryption**:
```
shared := ECDH(esk, parse(ct_d))
k_d := HKDF-SHA-256(shared; ⊥, DS_deliver ‖ H(o))
s := XChaCha20-Poly1305_Decrypt(k_d, nonce, ct, AAD = DS_deliver-ad ‖ H(o))
```

**安全属性**：
- esk 永远不出 client 进程；epk 在 `o.bind.recipient_epk` 里被 channel binding β 覆盖（防 MITM 替换）
- 任何中间人（Pro relay operator、ISP）即使看到所有 wire traffic 也无法解 `s`（无 esk）
- 这是真 E2E 加密的 export delivery，**不依赖 TLS** 提供 confidentiality
- 详细论证见 SUDP paper §09-security-analysis.tex Proposition non-disclosure

### 4.5.1 Reveal (SafeClaw 扩展，明文返回)

T 收到 `type=reveal` op 验证通过后:
```
s := M[o.act.target]
Response: 200 OK, body = { value: <s as plaintext string> }
```

**与 export 的本质区别**：
- 不做 KEM Encap，不做 AEAD 加密
- response body 直接装 plaintext，**TLS 路径上的所有 trusted/中介节点都能看到**（含 SaaS 形态的 Pro relay）
- AV / OB / RR 三 property 与 export 完全一致；仅 non-disclosure 让步

**适用场景**：
- transparent HTTP proxy UX 下 R 通过 `safeclaw-vault` 虚拟服务取 secret（详 §4.6）
- R 没有 ECDH 客户端能力（任何不 import SafeClaw lib 的标准 HTTP client）
- toy / game demo（无真凭据，安全主张退化可接受）

**不适用**：跨 trust boundary 投递严格 secret（用 export）；migration 跨设备的 self-import（用 export with U's own pk）。

### 4.6 Proxy port (separate)

Agent (R) 通过 `:23295/<service>/...` 发请求。Daemon 的处理流程（详 `src/core/router.rs::proxy_handler`）：

1. 解析 service name + upstream path
2. 检查 vault state：Locked → 返回 auto-formatted "vault locked" 响应
3. Policy 评估（详 §5.4）：
   - `allow` → forward
   - `ask` 且 cache hit → forward
   - `ask` 且 cache miss → 返回 `202 + approval_id`（agent 轮询）
   - `ask-always` → 返回 `202 + approval_id`
   - `deny` → `403`
4. Agent 轮询 `GET /approve/{id}` 直到 user 在 web UI 上 `confirm` 或 `reject`
5. Confirm 后 agent 下次 poll 触发 upstream forward
6. Forward 时按 `auth.type` 注入 secret（bearer/basic/header/oauth2/...），见 `src/auth/`

**Approval flow 跟 SUDP Phase II 的对应**:
- `r` = approval id (UUID v4) + 内部的 freshness state
- `o` = (service, method, path, body) 的 sanitized 版本（user 在 web 上看到的就是 `Render(o)`）
- `σ_c` = `POST /approve/{id}/confirm` 时的 WebAuthn assertion
- 见 SUDP paper §05-sudp-protocol/05-phase2-grant.tex 关于 R↔U OOB channel 的描述

### 4.6.1 内置虚拟服务 `safeclaw-vault`

为了让 R 透明取 stored secrets（无需懂 SUDP），proxy port 上注册一个内置虚拟服务 `safeclaw-vault`：

```
GET :23295/safeclaw-vault/<dotted-path>
    Authorization: Bearer <session-or-sc_xxx>
    [optional] X-Recipient-Epk: <base64 ECDH pk>      # 走 reveal vs export
```

**daemon 内部**:
1. 识别 `safeclaw-vault` 是内置虚拟服务（不是 upstream HTTP forward）
2. 解析 `<dotted-path>` 为 `o.act.target`（如 `services.openai.api_key`）
3. `X-Recipient-Epk` header 决定 type：缺则 `reveal`，存在则 `export` 并把值放进 `o.bind.recipient`
4. policy 评估走 §5.4
5. 需要 approval 时：渲染 approve 页 → user passkey → 浏览器把构造好的 grant 提交到 `:23294/grant`
6. T 派发 `handle_reveal` 或 `handle_export`，结果存到 approval state
7. R 轮询 `:23295/...` 拿结果（与其他 service 一致）

**对 R 的关键性质**:
- R 不构造 SUDP `o`（adapter 在 T 一侧自动 canonicalize HTTP 请求 → `o`）
- R 不签 grant（R 没 passkey）
- R 永远只看见 HTTP，**完全 SUDP-unaware**
- 这就是 paper §05-agentic-systems "tool adapter compiles into o" 的 T-side adapter 实例化（详 paper feedback proposal #1）

### 4.7 Vault selection

Vault 选择由 URL path 的 `{vid}` segment 承载（详 §4.0），不再使用 `X-Safeclaw-Tenant` header。Custodian 不感知 user—principal→vault 的映射是部署层职责，custodian 只看 `{vid}`。

State dir 路由：`<state_dir>/vaults/<vid>/vault.dat`。单 vault 部署本质是多 vault 的 N=1 case，无特殊路径。

---

## 5. Storage Layout

### 5.1 `vault.dat` SCSV format

**S**afe**C**law **S**ealed **V**ault format，单文件取代 v0.5.0 的 `vault.enc + wrapped_dek_<credId>.bin` 双文件。

**Atomicity**: 一次 atomic rename 提交所有变更（`tmp` 写完 fsync → rename）。满足 SUDP §05-sudp-protocol/06-phase3 III.3 的 atomic invariant 要求。

**File layout** (binary, big-endian):

```
Offset  Size                 Field
──────  ──────────────────   ─────────────────────────────────────────
0       4                    magic = "SCSV"
4       2                    version = 0x0001
6       2                    reserved = 0x0000
8       2                    cred_count
10      cred_count × N       DekWrapEntry × cred_count    [N varies]
...     24                   body_aead_nonce
...     remaining            body_ciphertext ‖ AEAD tag
```

**DekWrapEntry layout**:

```
Offset  Size            Field
──────  ──────────      ─────────────────────────────────────────
0       2               entry_length (excluding this field)
2       2               cid_length
4       cid_length      credential_id (raw bytes)
4+L     32              η_c (per-credential PRF salt)
36+L    24              wrap_aead_nonce
60+L    48              wrapped (32B ciphertext + 16B Poly1305 tag)
                        = AEAD(W_c, K, AAD = DS_wrap ‖ ver ‖ cid_c)
```

**Body AEAD**:
```
plaintext = JSON(M)       # M schema 见 §5.2
nonce     = body_aead_nonce
AAD       = DS_state ‖ u16_be(version) ‖ body_aead_nonce
ct        = XChaCha20-Poly1305_Encrypt(K, nonce, plaintext, AAD)
```

**实现位置**: `src/crypto/sealed_vault.rs`（待重构合并 `dek_wraps.rs` + `vault_file.rs`）。

### 5.2 Vault plaintext (M) schema

```json
{
  "services": {
    "openai":    { "api_key": "sk-...", "memory_ttl": -1 },
    "anthropic": { "api_key": "sk-ant-..." },
    "gmail":     { "oauth_refresh_token": "...", "memory_ttl": 1800 }
  },
  "policy": {
    "default_levels": { "ask": "ask-always", "...": "..." },
    "rules": [
      { "id": "<rule_id>", "match": "POST /v1/...", "level": "ask", "ttl": 3600 }
    ]
  },
  "preferences": {
    "model": { "primary": "..." }
  },
  "peer_keks": {
    "<cid_b64>": "<base64 W_c>"
  },
  "vapid_private_key": "..."
}
```

**字段说明**:
- `services.*`: per-service config + auth + 可选 `memory_ttl`（详 §6.1）
- `policy`: standing authorization 规则（SUDP §02 "Policy"）
- `preferences`: 不归 SafeClaw 解析的 frontend 配置（OSS daemon 不写）
- `peer_keks`: SUDP rotation 的 in-state peer map（每次 write op 由 acting credential 更新自己的 entry，对其他 credentials 用缓存的 W_c 重新 wrap K'，详 SUDP paper §05-sudp-protocol/06-phase3-consumption.tex Default recoverability policy）
- `vapid_private_key`: Web Push key（如保留 Web Push 功能）

**未含**:
- `files`: v1 不含，推迟到 v1.1
- `audit`: 永远不进 vault（独立 `audit.db`）

### 5.3 Directory layout

**单租户部署**（OSS 自托管 / openclaw bundle / 本地 CLI）:

```
~/.safeclaw/
  vault.dat                      # ★单文件 SCSV
  vault.dat.bak.1                # 自动备份（可选）
  passkeys.json                  # 注册的 passkey 列表（pub material only）
  known_servers.json             # ★Client TOFU pinning（仅 remote mode CLI 才创建；local mode 用户无此文件）
  audit.db                       # SQLite 审计
  config.toml                    # 用户配置
  services/                      # 用户安装的社区 service
  crypto/
    README.md                    # 说明：以下文件仅用于 HPKE outer envelope (§4.2)，
                                 #       与 vault 加密无关；丢失不会锁死 vault
    sc_pk.jwk                    # daemon 静态 X25519 public key
    sc_sk.jwk                    # daemon 静态 X25519 secret key
```

**多租户部署**（safeclaw.pro SaaS）:

```
/var/lib/safeclaw/
  config.toml
  crypto/                        # daemon 全局共享（HPKE keypair 不分 tenant）
    sc_pk.jwk
    sc_sk.jwk
    README.md
  tenants/
    <tenant_id_1>/
      vault.dat
      passkeys.json
      audit.db
      services/
    <tenant_id_2>/...
```

**关键不变量**：
- daemon binary 同一份；无 `--multi-tenant` flag——是否多租户由 state dir 是否含 `tenants/` 子目录决定（约定优于配置）
- HPKE keypair `sc_*.jwk` 是 daemon 全局，**不分 tenant**（仅 transport 加密）
- 每 tenant 各自独立 vault.dat / passkeys / audit / services，跨 tenant 永远隔离
- `<tenant_id>` 是 opaque 字符串（UUID 或类似），daemon 不解释其语义

**关键变化 vs CHO §6**:
- CHO 当时把 `sc_*.jwk` 标为"vault 加密的一部分，删除会锁死 vault" — 那是 v0.5.0 的 dual-role；**v1 不再如此**
- v1 `sc_*.jwk` 仅做 transport encryption；丢失只影响 client 需要重新 TOFU
- `wrapped_dek_<credId>.bin` 全部合并进 `vault.dat`（CHO 那部分目录条目移除）
- 新增 `known_servers.json`（CLI-side state，跟 vault/daemon 无关）
- 多租户布局：用 `tenants/<id>/` 子目录隔离每个租户

详细解释见 `../SAFECLAW_V1_DESIGN_HANDOFF.md` §6。

---

## 6. Policy & Memory Residence

### 6.1 三层独立 TTL

完整模型见 SAFECLAW_V1_DESIGN_HANDOFF.md §7。简略：

| Layer | 字段 | 作用 |
|---|---|---|
| Operation 自身有效期 | `o.valid.expiry` | 单次 op 的 validity（本 profile = freshness TTL）|
| Policy cache TTL | `policy.rules[].ttl` | "approve 一次后，N 秒内同类自动放行" |
| Memory residence TTL | `services.<name>.memory_ttl` | secret 在 daemon 内存里的存活时间 |

**TTL 不在 SUDP `o` 里**。它们是 deployment-level 配置。SUDP `Policy(cid_c, o)` 是 stateful predicate，本 profile 显式声明 Policy 持有 TTL cache state。

### 6.2 Memory residence default + override

**Daemon 内存 layout**（unlocked 状态）：

```
Runtime metadata (无 secret，可一直驻留):
  - policy rules
  - service definitions
  - peer_keks (per-credential W_c)
  - preferences

Secrets cache (per-service):
  HashMap<service_name, (auth_value, expires_at)>
  ├─ allow 服务: unlock bootstrap 时填，按 memory_ttl evict
  ├─ ask 服务: approval-confirm 后填，按 rule.ttl evict
  └─ ask-always 服务: 永不进 cache

NOT in memory:
  - M plaintext as a single object（解构后丢）
  - K (DEK)，W_c (userKey)：unwrap 后立即 zeroize
  - 任何 ask/ask-always 服务的 auth（未在 cache 时）
```

**Default `memory_ttl`**（按 effective `policy.level` 派生）:

| `policy.level` | 默认 `memory_ttl` | secrets_cache 行为 |
|---|---|---|
| `allow` | `-1` (∞，等于 unlocked 期间) | bootstrap 即填 |
| `ask` | = `rule.ttl` | approval-confirm 后填，TTL 到 evict |
| `ask-always` | `0` | 不进 cache |
| `deny` | N/A | 永远拒 |

User 可在 vault `services.<name>.memory_ttl` 显式覆盖。

**Invariant**: `services.<name>.memory_ttl >= rule.ttl` for any matching `ask` rule（写 vault 时 validate）。

### 6.3 Vault state semantics (Locked / Unlocked)

| State | 行为 |
|---|---|
| **Unlocked** | 接受 op；按 policy 走；secrets_cache 各 entry 独立 expire |
| **Locked** | 仅接受 **lifecycle bypass** op（`Enroll` + `Custom("vault-unlock")`）；其余 op 创建直接 409 `vault locked — unlock first`；proxy（`/use`）返 auto-formatted "vault locked" 响应 |

**State transitions** — 都是标准 sudp `Custom(String)` op，走 `POST /v/{vid}/op` + `POST /op/{op_id}/approve` 标准两步：

| Op | Effect |
|---|---|
| `Custom("vault-unlock")` | 解锁：decrypt M（用 grant 携带的 W_c），bootstrap secrets_cache（对 default-read=`allow` 的 service，把 resolved auth 装进 mem），把所有 target plaintexts 返给 requester（user 编辑器复用此响应，免一次额外 ceremony）。进入 Unlocked。 |
| `Custom("vault-lock")` | 锁定：清空 secrets_cache + 进入 Locked。Grant required —— lock 本身是 daemon state mutation，SUDP 不变量"U-attested state changes only" 同样适用（否则任何持 session token 的 attacker 可以 DOS-lock）。 |
| `Enroll` | First-time setup：建 vault 后 **auto-unlock**（W_c 已在 grant 里，inline bootstrap，省一次 ceremony）。 |

**Custom 变体的 paper 定位**：SUDP 协议层只承诺 6 个 core acts (Use/Export/Write/Rotate/Enroll/Revoke) 的语义+安全证明；`Custom(name)` 是 deployment 扩展槽，享受 grant machinery 但 dispatch 自定义。SafeClaw 用 `vault-unlock` / `vault-lock` 表达 lifecycle 而非污染 SUDP 表面。

**Daemon-side auto-lock timer = 不引入。** 它会等价于把所有 `allow` 政策变成 "ask every N minutes"，违背 `allow` 语义（"once unlocked, no further friction during session"）。Lock 永远是 user-initiated，daemon 仅在进程重启时实质重置（vault_states 不持久化，重启 = 全部 Locked）。

不引入 "session" 概念。

### 6.4 Policy 形式化

```
T.policy_state = {
  approval_cache: HashMap<(cid_c, rule_id), (approved_at, ttl)>,
  ...
}

Policy(cid_c, o):
  rule = match_rule(o, M.policy.rules)  // specificity-scored matching
  case rule.level:
    "allow"       => admit
    "deny"        => reject
    "ask-always"  => not admitted (must trigger approval flow each time)
    "ask"         => 
       if approval_cache contains (cid_c, rule.id) and not expired:
         admit
       else:
         not admitted (must trigger approval flow)
```

**Specificity scoring** (`src/core/policy.rs`):
- `+1000` if rule has body regex
- `+5` if method specified
- `+10` per literal (non-wildcard) path segment

最高分匹配 wins。详 v0.5.0 沿用，本 profile 不改。

---

## 7. Channel Binding β

按 SUDP §05-sudp-protocol/05-phase2-grant.tex II.2:

```
β = SHA-256(DS_bind ‖ 0x00 ‖ r ‖ H(canonical(o)))
```

实现 `src/crypto/binding.rs::compute_binding`。

**WebAuthn challenge re-binding** (`src/passkey/webauthn.rs::verify_assertion`):

```
expected_challenge = β
parse client_data_json
require base64url_decode(client_data_json.challenge) == β
```

防止 client 在 WebAuthn ceremony 里塞进任意值绕过 channel binding。

---

## 8. Phase III.3 Atomicity (Rotation)

按 SUDP §05-sudp-protocol/06-phase3-consumption.tex III.3:

每个 `write/enroll/revoke` op 必须做：
1. fresh `K' \stackrel{\$}{\gets} CSPRNG`
2. fresh `η_c^next` (acting credential 的下一个 PRF salt)
3. `C' = Enc_{K'}(M'; AAD = DS_state ‖ ver)`
4. `\widehat{K}_c^new = Wrap_{W_c^new}(K')`，其中 `W_c^new = HKDF(...; salt = η_c^next, ...)`
5. 对所有其他 credential `c' \neq c`: `\widehat{K}_{c'}^new = Wrap_{M.peer_keks[c']}(K')`
6. **atomic 提交**: 写 `vault.dat.tmp` (含新 entries + new body) → fsync → rename

**Crash invariant**: 满足 atomic single-rename，任何 crash 都不会留下不可恢复的中间态。这是 v1 SCSV 单文件 format 相对 v0.5.0 双文件方案的核心改进。

---

## 9. Residuals & Limitations

### 9.1 Peer-map dormancy

如 SUDP paper §05-sudp-protocol/06-phase3-consumption.tex 所述：multi-credential 部署中的 in-state peer map 有一个 residual：单个 credential `c` 被 transient 攻陷时，其 peer `c'` 在 `c'` 自己的下一次 rotation 之前，存量 wrap entry 仍可被攻陷者 unwrap。

本 profile 沿用 paper 的 default policy（in-state peer map），这个限制照样 disclosed。

### 9.2 Memory residency vs. process compromise

Daemon 跑在 user 自己的 process 内。一个能读 `/proc/$pid/mem` 的 attacker 可以在 secrets_cache 里看到任意 hot/warm secret。本 profile 跟 v0.5.0 一致，**不主张** memory-resident attacker 抵抗（详 SAFECLAW_V1_DESIGN_HANDOFF.md §10/§11 future work）。

### 9.3 Audit log integrity

`audit.db` 为普通 SQLite，无 hash chain。本 profile 不主张 audit tamper-resistance（user 自己机器可写自己的 file）。

### 9.4 E-side rotation

`safeclaw` 不主动 rotate provider 端的 long-lived API key。这是 deployment 责任。Future work 可能通过 `[[rotate]]` recipe in service.toml 支持。

### 9.5 Files vault

v1 不含 file storage。Future v1.1 加进来作为 `o.act.target = files.<id>` 的 export/write 子类。

### 9.6 sc_pk rotation

v1 不主动 rotation HPKE 静态 keypair。Future work:
- `safeclaw rotate-server-key` CLI 命令：生成新 sc_pk/sc_sk，原子替换，warning 用户所有 client 第一次连接会看到 fingerprint mismatch（必须 OOB 验证后重新 pin）
- 自动 rotation cadence（如 6 月一次）— deployment policy 决定
- 如果 sc_sk 怀疑泄露（例如服务器被入侵但 vault.dat 没动）— 用户应当主动 rotate

由于 sc_sk 仅 transport-only，rotation 不影响 vault 数据；但所有 client 需要重新 TOFU。

### 9.7 Concurrent operations

- `with_vault_mut` 用 `state.write_mutex` 串行化 write/enroll/revoke ops（per-process mutex）
- `Custom("vault-unlock")` 是幂等的：重复 unlock 刷新 secrets_cache + `unlocked_at`（最后一次 win，覆盖前一次的 cache）
- `Custom("vault-lock")` 是 idempotent + atomic：清空 cache 一次性
- 同一时刻只允许一个 grant 在 II.3 → III 之间（避免对同一个 r 的并发消费——`ChallengeStore.take` 有 atomic 语义）

---

## 10. Concrete examples

### 10.1 setup ceremony

```
Step 1: client → GET /challenge
  Response: { r: "...", expires_at, credentials: [] }   (没 cred 因为还没 setup)

Step 2: client 生成 fresh keys + 做 WebAuthn create()
  cid, x, y ← navigator.credentials.create({...})
  η_initial ← random 32B
  rawPRF ← PRF eval(η_initial)
  user_key_initial ← HKDF(rawPRF; salt=η_initial, info=DS_userkey ‖ cid)

Step 3: 组装 grant + 发送
  o = {
    act: { type: "setup", target: "vault", scope: { passkeys: [...], initial_M: {...} }},
    bind: { redeemer: T_id },
    valid: { expiry: r.expires_at }
  }
  β = SHA-256(DS_setup ‖ r ‖ H(canonical(o)))
  σ ← navigator.credentials.create() 顺带产生 attestation
  POST /grant { o, r, credential_id: cid, user_key: user_key_initial, assertion: ... }

Step 4: server
  - HPKE Open envelope (§4.2) → recover grant
  - validate grant per §4.4
  - generate K, encrypt M, wrap K under W_initial, write vault.dat
  - return 200
```

### 10.2 export op (e.g. `safeclaw service connect anthropic` 反查 stored key)

```
Step 1: client → GET /challenge
Step 2: client 生成 ephemeral ECDH keypair (esk, epk)
Step 3: o = {
  act: { type: "export", target: "services.anthropic.api_key", scope: {} },
  bind: { redeemer: T_id, recipient: epk },
  valid: { expiry: r.expires_at }
}
Step 4: 做 WebAuthn get() with challenge=β, 拿 σ
Step 5: POST /grant { o, r, credential_id: cid, user_key: W_c, assertion: ... }
Step 6: server validate + Encap(epk) + 加密 s + return π = { ct_d, delta }
Step 7: client Decap(esk, ct_d) → k_d → 解开 delta 得到 s
```

### 10.3 write op (rotate K + 写 services.openai)

```
Step 1: client → GET /challenge
Step 2: WebAuthn get() 同时做两次 PRF eval:
  - PRF(η_c)         → user_key (用于 unwrap 当前 K)
  - PRF(η_c^next)    → user_key_next (用于 wrap K')
  η_c^next 随机生成，进 o.act.scope
Step 3: o = {
  act: { type: "write", target: "services.openai", scope: { patch: {...}, η_next: ... } },
  bind: { redeemer: T_id },
  valid: { expiry: r.expires_at }
}
Step 4: POST /grant { o, r, credential_id: cid, user_key, user_key_next, prf_salt_next, assertion }
Step 5: server validate + 走 Phase III.3:
  - unwrap K_old via W_c
  - decrypt M, apply patch
  - generate K' fresh
  - wrap K' for acting cred under HKDF(W_c^next; salt=η_c^next, ...)
  - wrap K' for each peer cred under M.peer_keks[c']
  - encrypt new M' under K'
  - atomic write vault.dat
```

---

## 11. Cross-reference index

| 想找 | 看哪儿 |
|---|---|
| SUDP roles 形式定义 | paper §05-sudp-protocol/00-roles-patterns.tex |
| Key hierarchy 推导 + figure | paper §05-sudp-protocol/01-protected-state.tex |
| Phase II grant flow + figure | paper §05-sudp-protocol/05-phase2-grant.tex |
| Phase III dispatch + figure | paper §05-sudp-protocol/06-phase3-consumption.tex |
| 安全性证明 (AV / OB / RR / non-disclosure) | paper §09-security-analysis.tex |
| 本 profile 的算法选择 | 本文 §2 |
| Endpoint 实现位置 | `src/server/routes.rs` |
| Channel binding 代码 | `src/crypto/binding.rs` + `canonical.rs` |
| Vault file format 代码 | `src/crypto/sealed_vault.rs`（待重构） |
| WebAuthn assertion verify | `src/passkey/webauthn.rs` |
| Policy engine | `src/core/policy.rs` |
| Approval workflow | `src/core/approval.rs` |
| CLI architecture | `../CLI_DESIGN_HANDOFF.md` |
| 整体设计 + SUDP 对齐决策 | `../SAFECLAW_V1_DESIGN_HANDOFF.md` |

---

文档结束。
