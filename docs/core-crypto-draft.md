# A Formalization and Construction of a Secret-Use Delegation Protocol for Agentic Systems
We study capability-constrained secret use in agent-mediated systems and formalize a secret-use delegation protocol with user-mediated, transaction-bound authorization.

## Problem Formulation and Security Model

### System Setting and Parties

- We study **secret-backed operations** in a vault-backed service setting.
- A user stores protected secret state in a **vault**, while a **proxy** mediates access to and controlled use of that state.
- The goal is to enable authorized secret-backed operations without exposing the underlying secret to untrusted requesters.


#### Parties and Roles
- **Authorizer** (\(U\)): the user whose approval governs access to secret-backed operations.
- **Requester** (\(R\)): the party that initiates an operation request.
- **Proxy** (\(P\)): the protocol-speaking service that validates authorization, redeems grants, and consumes them over protected state.
- **Vault** (\(V\)): the protected state object storing sealed secret material; it is managed by \(P\) and is not an independent protocol-speaking party.

relationship:
- \(R\) and \(U\) may coincide or be distinct.
- \(P\) is distinct from \(U\) and serves as the enforcement point of the protocol.
- \(V\) is a protected object, not a protocol principal.

### Trust Assumptions and Adversary Model
### Security goals (and Non-goals)

定义一个清晰的问题类与安全模型：agent 可发起请求但不可得 secret；用户介导 release；proxy 受限 TCB 内消费；导出必须是接收者保护的密文包。

问题类 / security objective: Capability-Constrained Secret Use


末尾段落提一下：
The protocol supports two execution patterns. In delegated execution, the requester and the authorizer are distinct, as in agent-initiated secret-backed operations requiring subsequent user approval. In direct execution, the requester and the authorizer coincide, allowing the online authorization steps to execute in a collapsed form.


## Core Protocol: Secret-Use Delegation Protocol
The abstract protocol below covers both delegated and direct execution; the difference lies only in whether the grant protocol is executed explicitly across distinct parties or collapsed by a single requester-authorizer.

### Phase I: Setup
TBD:
user/authenticator registration
proxy verification state
sealed vault state initialization
policy root / versioning metadata


### Authorized Operation and Grant

TBD: 定义 op_desc：
operation type
vault identifier
scope
recipient
nonce
expiry
aux?: argument digest version
TODO: 这个非常需要打磨，

一个好的𝑜，应当恰好编码这三类东西：
第一，授权语义：到底批准什么操作；
第二，兑现边界：谁能 redeem，若有导出则交给谁；
第三，有效性约束：多久有效、如何防 replay、如何与本次协议实例绑定。
---

We model an **authorized operation** as a canonical protocol tuple which captures the intended secret-backed action together with the information to be bound by authorization, redemption, and subsequent consumption. 

**Definition 1 (Authorized Operation).**  
An authorized operation is a canonical protocol tuple
\[
o := (\mathsf{type}, \mathsf{target}, \mathsf{constraints}, \mathsf{redeemer}, \mathsf{expiry}, \mathsf{nonce}),
\]
where:

- \(\mathsf{type}\) specifies the semantic class of the authorized secret-backed action; 目前就2类：use, export，对应phase iii 里的2种
- \(\mathsf{target}\) identifies the protected object to which the operation applies;
- \(\mathsf{constraints}\) denotes the canonical encoding of all additional security-relevant conditions whose modification would change the authorization meaning of the operation, excluding information already represented by the other tuple components;
- \(\mathsf{redeemer}\) identifies the party entitled to redeem the resulting grant;
- \(\mathsf{expiry}\) specifies the validity bound of the authorization; and
- \(\mathsf{nonce}\) provides freshness and replay protection.

Thus, \(o\) captures exactly three aspects of authorization semantics: what secret-backed action is being approved, who may redeem the resulting grant, and under what validity conditions the authorization remains exercisable.

**Definition 2 (Grant).**  
A grant \(g\) is a protocol artifact representing successful authorization of an authorized operation \(o\). Concretely, a grant binds \(o\) together with the authorization evidence and associated protocol metadata required for later redemption and consumption.

A valid grant semantically confers a scoped secret-use capability for the corresponding authorized operation.


### Phase II: Authorization Grant Protocol

1. Grant Request
2. User Authorization
3. Grant Redemption
- optional: the grant is PoP-bound at redemption

--- 辅助性参考：

因为在 OAuth 术语里，authorization 和 authorization grant 不是一个东西。
RFC 6749 直接把 authorization grant 定义为：
“a credential representing the resource owner’s authorization”。
也就是：

authorization = 授权这个行为 / 决定
grant = 承载该授权结果的协议工件/credential

这和你们现在的抽象非常贴：
用户批准是一回事；批准后 proxy / requester 可拿来继续流程的那个 artifact，又是另一回事。

所以 Authorization Grant Protocol 的语义是：

这是一段把授权决定变成可兑现 grant 的协议。


--- 补充：
这section合适地方解释一句：when requester = authorizer, the grant protocol may be executed in a collapsed form

### Phase III: Grant Consumption
Grant consumption admits two principal forms. In the first, the granted capability is consumed internally by the proxy without releasing an extractable secret outside the trusted execution boundary. In the second, consumption results in a recipient-protected delivery artifact, enabling controlled extraction without exposing the underlying secret in plaintext during transit.

#### Non-Extracting Consumption
指：
grant 被消费后
secret-use capability 只在 proxy 侧内部被使用
明文 secret 不离开 proxy 的受信执行面

#### Recipient-Protected Extracting Delivery
指：
grant 被消费后
产出一个发给接收方的 artifact
但它不是裸明文，而是 recipient-protected 的
只有目标接收方能恢复或使用


### Protocol Extensions: Rewrap and Rotation
Beyond the core authorization and consumption flow, the protocol may support lifecycle extensions such as rewrap and rotation. These operations do not introduce a new authorization model, but extend the protocol to maintain or update sealed secret state over time.

## Concrete Construction
这一节统一写：

How the abstract protocol is instantiated
Why these primitives satisfy the required properties

也就是说：

PRF requirement → WebAuthn PRF
- 如果你在 Section 3 具体实例化到 WebAuthn，再提 credential registration 或 registration ceremony
Key wrapping requirement → AES-KW or AEAD-based envelope
Context binding → HKDF info
Authenticated channel → TLS

不要写成“我们选择了什么算法”，
而是写成：

The abstract protocol requires X, Y, Z properties.
We instantiate them as follows.
------
一种可能的写法：

认证/用户介导层：WebAuthn/Passkey 提供“受用户同意约束的凭据使用”，并在 PRF/hmac-secret 扩展下可导出作用域化对称材料，用于数据加密/签名。你们的“现场 derive”应明确引用这类能力边界，同时在论文里解释 PRF 绑定 passkey 带来的删除/恢复风险（W3C 的 passkey endpoints 文档专门提醒 relying party：若 PRF 被用于加密用户数据，删除 passkey 会影响数据）。

能力绑定/抗转用层（PoP / sender-constraining 思想）：如果你们的 capability/授权工件会在 client↔proxy 之间流转（哪怕只在一次请求中），用“sender-constraining / PoP 绑定到请求”解释其抗重放目标，会比自造“context-bound”概念更主流。DPoP 是明确以“sender-constraining token”作为抽象来写的。

密钥派生层（Key schedule）：强烈建议以 HKDF（extract-then-expand）为核心表达 key schedule，并解释域分离（不同 info 派生不同子密钥）。HKDF 在 IETF RFC 5869 中被定义成可作为多种协议的构件；NIST SP 800-56C 也系统性讨论了 extract-then-expand 的 KDF 建议。

封存/包裹层（Sealing / wrapping）：用于 wrapped_DEK 的 primitive，建议优先引用 NIST SP 800-38F（KW/KWP）或对应的 IETF RFC 3394/5649（AES-KW/AES-KWP），因为它们是“专为包裹密钥材料设计”的标准，而不是随意用 AEAD 去加密一个 key blob。

消息保密（export 包）层：
- 若 export 的接收者就是当次会话的 client，并且 client 拥有与 proxy 同源的派生材料：可以用 AEAD（加 AAD 绑定 request descriptor）加密 payload；
- 若 export 需要面向一个“独立接收者公钥”（比如跨设备、异步、或由另一端恢复）：建议用 HPKE（RFC 9180）而不是自造 ECIES。HPKE 是 IETF 对“混合公钥加密”模式的标准化抽象，能把 KEM/KDF/AEAD 组合得更规范。

通道层：你们不需要在论文里把 TLS 当作创新点，但应明确把它作为网络对手模型下的传输假设，并说明你们的协议不是替代 TLS，而是定义在其之上的应用层授权+密钥生命周期协议。TLS 1.3 RFC 的抽象（防窃听、防篡改、抗伪造）可作为你们 transport assumption 的引用依据。

-----

给出现成标准构件的实例化（profile）：WebAuthn PRF + HKDF + NIST key wrap / AEAD +（可选 HPKE）+ TLS 作为传输假设。

## Appliction binding: Vault-backed service model
这一层讲：SUDP layer之上，如何构建面向agent的 vault-based SUDP 系统模型（application binding）

proxy 作为协议说话者，vault 作为受保护状态对象
vault state 的抽象结构
service 如何引用 vault / secret
export / use / rewrap 如何映射到具体服务能力
哪些 policy 进入 constraints，哪些只是本地实现策略

## Security Discussion / Analysis

这一节单列。

你必须解释：

为什么 agent 无法获得 secret
为什么磁盘泄露不导致明文恢复
为什么 export 不破坏模型
为什么 replay 无法扩大权限
rewrap 是否保持 forward security



## related works (paper-only, low priority，优先把前面的spec按顶会paper写完)
Capability-Constrained Secret Use (有这个吗?)
Delegation protocols
Proof-of-possession–bound authorization
Capability-based security
User-mediated authorization (WebAuthn)
Key-release systems
Split-knowledge / dual control

（此处省略很多related work draft）
因此，合理的贡献陈述方式
基于上述版图，你们最稳妥、最“顶会友好”的贡献写法是：

定义一个清晰的问题类与安全模型：agent 可发起请求但不可得 secret；用户介导 release；proxy 受限 TCB 内消费；导出必须是接收者保护的密文包。
提出一个抽象协议模型（Abstract Protocol Model）：Setup/Enrollment + Capability Grant Ceremony（PoP-bound、带约束）+ Consumption（按是否可导出进行本质划分）。
给出现成标准构件的实例化（profile）：WebAuthn PRF + HKDF + NIST key wrap / AEAD +（可选 HPKE）+ TLS 作为传输假设。
这样写，你们不是靠“新词汇搜不到工作”来证明新颖性，而是用系统化的 related work 版图证明：现有工作覆盖子问题，但缺少对你们 problem class 的统一协议定义；你们做的是“第一个明确的 profile/组合协议”，而不是“第一个发明 key release”。这会显著提高可信度与可发表性。


## TODO

3. done 业务流如何讲明白
流 1
agent 请求 proxy 使用某个 credential
proxy 生成一个 approval request
agent 把 link / id 发给 user
user 去 approve
agent 再去 redeem / continue
proxy 返回结果
流 2
user 自己通过 CLI 和 proxy 交互
对 vault read / write / export / use

4. request descriptor定义
一种可能但差一点：(operation_class, vault_id, target_service, recipient, scope, arg_digest, expiry, nonce)

5. 计划：把这个按paper标准完善，可以同时记录哪些在eng上怎么写之类；让claude基于这个补充具体协议细节；开新项目一键变成paper；继续完成本地cli设计，然后完善工程doc（我感觉doc除了密码学以外还需要几个独立doc/section 才能讲的清楚）