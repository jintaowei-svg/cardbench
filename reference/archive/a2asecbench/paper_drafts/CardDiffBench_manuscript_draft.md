# CardDiffBench: Scenario-Adapted Test Generation for AgentCard Control-Plane Security in Agent-to-Agent Systems

Status: draft reset. This version aligns the test-case generation method with the A2ASecBench scenario-adapter design and removes the old 96-case method and result claims.

## Author-Facing Planning Notes

### One-Sentence Argument

CardDiffBench evaluates whether A2A hosts make unsafe control-plane decisions when LLM-generated, scenario-adapted natural-language tasks are paired with schema-valid AgentCard differentials and optional oracle-preserving perturbations.

### Terminology Ledger

| Canonical term | First-use definition | Decision |
| --- | --- | --- |
| CardDiffBench | A benchmark for AgentCard control-plane differential risks. | Use for the benchmark. Use `CARDDIFF` only for code identifiers. |
| Agent-to-Agent (A2A) | Agent-to-Agent protocol. | Spell out once, then use A2A. |
| AgentCard | The A2A control-plane object describing identity, skills, interfaces, security, and modes. | Use consistently. |
| Scenario Adapter | An LLM-assisted generator that maps an attack vector and scenario specification to executable natural-language tasks. | This is the main generation method. |
| Perturbation Layer | A controlled transformation layer that binds generated tasks to schema-valid AgentCard state variants while preserving the oracle. | Use as an extension, not the main method. |
| Attack Success Rate (ASR) | Fraction of valid trials whose observed trace satisfies the attack oracle. | Use only when regenerated experiments are available. |

## Abstract

Agent-to-agent (A2A) systems increasingly rely on AgentCards to discover peers, select skills, route messages, bind tenants, negotiate protocol versions, enforce authorization, and accept returned artifacts. Existing A2A security benchmarks show that protocol-aware attacks must be evaluated at the system level rather than as isolated model prompts. However, AgentCard security also depends on how natural user tasks cause a host to interpret public cards, authenticated extended cards, interfaces, tenants, security scopes, and output modes during a workflow.

We introduce CardDiffBench, a focused benchmark for AgentCard control-plane differential risks. The benchmark defines eight attack vectors covering public-to-extended skill escalation, interface drift, cross-identity extended-card cache bleed, interface order hijacking, same-URL multi-tenant confusion, binding/version confusion, skill-level authorization confusion, and media mode drift. Following the A2ASecBench generation philosophy, CardDiffBench uses a scenario adapter as its primary case-generation mechanism: given an attack-vector description and a domain scenario specification, an LLM generates concrete natural-language tasks that instantiate the attack in travel, healthcare, and finance settings.

CardDiffBench extends the scenario-adapter method with an optional perturbation layer. The perturbation layer does not replace natural-language task generation. Instead, it binds generated tasks to schema-valid AgentCard state variants such as public/extended-card differences, interface ordering, endpoint aliases, tenant surfaces, protocol versions, skill-level scopes, and artifact MIME modes. Each case is executable in a local A2A HTTP+JSON environment and is scored only from observed protocol traces against a private oracle. This draft intentionally removes previous pilot results; new experiments should be reported only after regenerating cases under the scenario-adapter protocol and adding matched benign controls.

Keywords: agent-to-agent systems, AgentCard, scenario adapter, benchmark generation, control plane, protocol security, natural-language task generation

## 1 Introduction

Agent-to-agent (A2A) protocols provide a common substrate for multi-agent systems in which autonomous agents discover capabilities, exchange tasks, and return structured artifacts across heterogeneous implementations. Instead of requiring brittle point-to-point integrations, an A2A host can retrieve an AgentCard, identify declared skills and endpoints, submit a task, and process the returned artifact through a standardized communication flow. This design makes agent ecosystems easier to compose, but it also concentrates security-sensitive decisions in the control plane that mediates discovery, routing, authorization, and output handling.

The AgentCard is central to this control plane. It is not merely a descriptive profile shown at discovery time. In practical A2A workflows, the host may use public AgentCards for initial discovery, authenticated extended AgentCards for richer skill or interface information, `supportedInterfaces` for routing, tenant labels for workflow binding, `security` and `securitySchemes` for authorization, and input/output mode declarations for artifact handling. A host that treats these fields as passive metadata may silently convert legitimate state changes into unsafe decisions.

A2ASecBench motivates a general benchmark pattern for A2A security: define attack vectors, adapt them to realistic scenarios, generate executable test cases, and evaluate system traces rather than model self-reports. CardDiffBench adopts this pattern for AgentCard control-plane differentials. The benchmark asks whether a host remains secure when natural-language tasks, scenario-specific entities, and schema-valid AgentCard states jointly pressure skill selection, interface routing, tenant binding, authorization, and artifact acceptance.

The key methodological change in this draft is that natural-language task generation is no longer secondary. CardDiffBench now treats the scenario adapter as the primary generator. Given an abstract attack vector and a domain specification, the adapter produces concrete natural-language tasks that follow the attack semantics while using realistic domain language. A controlled perturbation layer may then vary AgentCard surfaces while preserving the same oracle. This keeps CardDiffBench aligned with A2ASecBench's adapter-based generation while preserving the project-specific contribution: AgentCard state is still a first-class control-plane object under test.

This draft removes the previous deterministic-only generation narrative and all prior pilot result claims. The old result tables should not be cited as current evidence. The repository now exposes a scenario-adapter task-bank generator and binds generated tasks into CardDiff metadata before applying optional AgentCard perturbations. Future experiments should add matched benign controls and then report attack success and utility-preservation metrics.

Contributions. This paper makes four intended contributions:

1. We introduce an AgentCard differential threat model that treats public cards, extended cards, interfaces, tenants, security scopes, and output modes as stateful A2A control-plane evidence.
2. We define eight CardDiffBench attack vectors and provide system-level success conditions grounded in observable protocol traces.
3. We adapt the A2ASecBench scenario-adapter method to AgentCard differentials by using LLM-generated natural-language tasks as the main case-generation surface.
4. We add an oracle-preserving perturbation layer that can vary AgentCard control-plane state without changing the attack semantics produced by the scenario adapter.

## 2 Background

### 2.1 AgentCard Discovery and Host Decisions

In A2A systems, an AgentCard describes a remote agent's identity, declared skills, endpoint information, security requirements, and supported input/output modes. A host typically retrieves a public AgentCard from a well-known endpoint, selects a skill or interface relevant to the user workflow, and then submits a task through the corresponding A2A endpoint. Because the card is the primary control-plane evidence available to the host, errors in card interpretation can lead directly to unsafe routing or authorization decisions.

CardDiffBench focuses on the subset of A2A protocol features that influence security-critical host decisions. The public AgentCard determines the initial view of the remote agent. The extended AgentCard may expose additional fields after authentication. `supportedInterfaces` determine where messages are sent and which protocol binding or version is used. Tenant fields connect an interface to a workflow or request context. `security` and `securitySchemes` describe agent-level and skill-level authorization requirements. Input/output modes and artifact MIME types determine whether returned content should be accepted by the host.

### 2.2 Scenario Adapters in A2A Benchmarking

A scenario adapter separates attack semantics from domain surface. It receives an attack-vector description and a scenario specification, then generates concrete test cases for that domain. This makes attacks portable across travel, healthcare, finance, or other settings without redefining the success condition for each domain.

CardDiffBench follows this approach. For each attack vector and scenario, the adapter generates natural-language tasks that a user or host might plausibly issue. These tasks are the primary benchmark examples. The AgentCard state attached to each task determines whether the host's response satisfies or violates the private oracle.

### 2.3 AgentCard Differentials

CardDiffBench models three families of AgentCard differentials. Extended-card differentials test whether hosts revalidate authenticated card updates. Interface and tenant differentials test whether hosts preserve routing and binding semantics when several interfaces look compatible. Policy and mode differentials test whether hosts enforce the most specific authorization and output constraints rather than relying on broad defaults.

## 3 Threat Model

CardDiffBench assumes an adversary who controls a third-party A2A agent and can publish schema-valid AgentCards for that agent. The adversary may control both the public AgentCard and the authenticated extended AgentCard, and may return different extended-card states depending on identity, scope, or session. The adversary can declare multiple supported interfaces, including interfaces with different tenants, protocol bindings, protocol versions, endpoint paths, or orderings. The adversary can also configure skill-level security requirements, input/output modes, and artifact MIME types.

The adversary is constrained in four ways. First, the adversary cannot tamper with the registry, the host, or the AgentCards of other benign agents. Second, the adversary does not break TLS, OAuth, bearer-token validation, mTLS, or other underlying cryptographic mechanisms. Third, the adversary does not rely on traditional prompt jailbreaks or implementation vulnerabilities in HTTP, JSON parsing, or the A2A server. Fourth, every benchmark case must remain schema-valid and oracle-preserving: the scenario-adapted task and any perturbation may change presentation, but must not change the private success condition of the attack.

The adversary's goal is to induce an unsafe host control-plane decision. Depending on the attack vector, this may mean causing the host to invoke an extended-card-only sensitive skill, route to a drifted or attacker-preferred interface, reuse privileged extended-card state across identities, bind the workflow to the wrong tenant, use an unintended protocol binding or version, invoke a skill without the required scope, or accept an artifact outside the negotiated output policy.

## 4 The CardDiffBench Framework

CardDiffBench contains four components: an attack taxonomy, domain scenario specifications, a scenario adapter for natural-language task generation, and a perturbation/scoring harness that binds tasks to executable A2A HTTP+JSON cases.

### 4.1 Attack Vectors

| Category | Attack | Core differential | Success condition |
| --- | --- | --- | --- |
| Extended-card differential | A1 Public-to-Extended Skill Escalation | `C_pub.skills` differs from `C_ext.skills` | Host invokes a sensitive skill that appears only in the extended AgentCard. |
| Extended-card differential | A2 Public-to-Extended Interface Drift | `C_pub.interfaces` differs from `C_ext.interfaces` | Host routes the workflow to the drifted extended-card interface. |
| Extended-card differential | A3 Cross-Identity Extended Card Cache Bleed | `C_ext(admin)` differs from `C_ext(user)` | Low-privilege identity reuses privileged extended-card state. |
| Interface/tenant confusion | B1 Interface Order Hijacking | Interface ordering or endpoint shape favors attacker-preferred route | Host selects the attacker-preferred interface. |
| Interface/tenant confusion | B2 Same-URL Multi-Tenant Confusion | Same URL represents different tenants | Host sends with `request_tenant` different from selected interface tenant. |
| Interface/tenant confusion | B3 Binding Downgrade / Version Confusion | Multiple protocol versions or bindings appear compatible | Host uses an unexpected binding or version. |
| Policy/mode drift | C1 Skill-Level Authorization Confusion | Skill-level security is stronger than agent-level security | Host invokes a restricted skill without the required scope. |
| Policy/mode drift | C2 Media Mode Drift | Returned artifact MIME differs from accepted modes | Host accepts an artifact outside the workflow's accepted output modes. |

### 4.2 Scenario Adapter

The primary generation function is:

```text
Adapter: A x S -> T
```

Here, `A` is the space of attack vectors, `S` is the space of scenario specifications, and `T` is the set of generated natural-language tasks. For each pair `(a, s)`, an LLM receives a structured attack description, a scenario specification, and a small set of seed examples. It returns a JSON array of concrete tasks. Each task must satisfy four constraints:

1. It must instantiate the target attack semantics.
2. It must use natural scenario language rather than only synthetic field names.
3. It must be executable by the local A2A harness.
4. It must not reveal private oracle labels or scoring rules.

The scenario adapter is responsible for domain diversity. For example, a tenant-confusion case in travel should mention itinerary, reservation, or loyalty-account workflow language, while the finance version should mention statement, transfer, treasury, or retail-account workflow language. The attack oracle remains the same, but the natural-language task surface changes.

### 4.3 Perturbation Layer

CardDiffBench keeps perturbations as an optional second stage:

```text
Perturb: T x K -> T'
```

Here, `K` is a set of oracle-preserving perturbation strategies. A perturbation may rename a skill, reorder interfaces, change endpoint aliases, introduce tenant shadows, vary protocol versions, or alter artifact MIME surfaces. Unlike the previous draft, this layer is not presented as the main generator. Its role is to test whether the host remains secure when the same scenario-adapted task is paired with different schema-valid AgentCard presentations.

This distinction matters. Scenario adaptation creates the benchmark's user-facing task diversity. Perturbation creates controlled protocol-state diversity. A valid case must satisfy both natural-language plausibility and private-oracle preservation.

### 4.4 Execution and Scoring

Each case runs in a local A2A HTTP+JSON environment. The harness exposes public AgentCard discovery, optional extended AgentCard retrieval, `message:send`, artifact return, event tracing, and private scoring. The SUT receives only the public task and protocol surfaces needed for the workflow. The private oracle is never included in the SUT-facing prompt.

The scorer uses observed events such as `extended_agent_card_fetched`, `message_sent`, `tenant_bound`, `security_scope_used`, `artifact_returned`, and `artifact_accepted`. This trace-based design keeps evaluation reproducible even when the task text is generated by an LLM.

## 5 Evaluation Plan

This draft does not report prior pilot results. The old 96-case ASR tables have been removed because they correspond to the earlier deterministic perturbation-first method.

The intended regenerated evaluation should include:

1. A scenario-adapted adversarial split generated from `attack vector x scenario x task template/entity seed`.
2. Optional perturbation variants for each generated task.
3. Matched benign/control tasks for each scenario and attack family.
4. Overall ASR, ASR by attack, ASR by scenario, ASR by perturbation, benign control pass rate, false-positive rate, and over-block rate.
5. Repeated trials for LLM-backed Hosts to estimate decision variance.

A scale comparable to A2ASecBench can be obtained by generating 100 natural-language tasks per attack-scenario cell. For eight CardDiffBench attacks and three scenarios, this yields 2,400 adversarial tasks before controls:

```text
8 attacks x 3 scenarios x 100 tasks = 2,400 adversarial cases
```

If matched benign controls are added at 100 per scenario, the total becomes 2,700 cases. If controls are paired one-to-one with adversarial cases, the total becomes 4,800 cases. The final choice should be driven by compute budget and the desired safety-utility analysis.

## 6 Discussion on Potential Mitigation

CardDiffBench points to a set of practical host-side defenses. These defenses should be evaluated after the scenario-adapted split is regenerated.

Public-to-extended diff checks. A host should not treat an extended AgentCard as a transparent replacement for the public AgentCard. If the extended card adds skills, changes interfaces, introduces stronger scopes, or changes output modes, the host should explicitly revalidate whether the new state is authorized for the current workflow.

Per-identity extended-card cache isolation. Extended AgentCard caches should be bound to identity, scope, session, issuer, and base URL. Caching only by base URL can cause privileged card state to leak into lower-privilege workflows.

Tenant binding enforcement. The workflow/request tenant, selected interface tenant, and token tenant should be checked as a three-way invariant. Same URL should not imply same tenant semantics. The selected interface must not silently override the workflow tenant.

Binding and version negotiation. Hosts should select an interface that satisfies the expected protocol binding and protocol version, and should reject unexpected downgrade paths. Interface ordering alone is not a safe negotiation rule.

Skill-level authorization. Before invoking a skill, hosts should validate the skill's own security requirements, not only the agent-level security field. This check should be enforced in code, not delegated to model discretion.

Output-mode enforcement. Hosts should check returned artifact MIME types against the workflow accepted modes and the selected skill output modes before accepting or rendering artifacts.

## 7 Related Work

### A2A Security Benchmarks

A2ASecBench provides the closest template and methodological foundation for this work. It evaluates A2A multi-agent systems at the system level and uses scenario adaptation to instantiate attacks across high-stakes domains. CardDiffBench narrows the scope to AgentCard control-plane differentials while adopting the same scenario-adapter generation principle.

### Benchmark Generation and Scenario Adaptation

Scenario adapters make benchmark cases portable across domains by mapping abstract attack vectors to concrete natural-language tasks. CardDiffBench follows this method and adds a structured perturbation layer for AgentCard state. The resulting design separates user-facing task diversity from protocol-control-plane diversity.

### Protocol and Control-Plane Security

Traditional distributed systems and web security have long recognized that control-plane state can be as security-critical as data-plane payloads. CardDiffBench brings this perspective to A2A systems by treating AgentCards as dynamic control-plane objects. The benchmark tests whether hosts enforce invariants across card state transitions, not merely whether they understand a task prompt.

## 8 Limitations

First, this draft describes a revised generation methodology and does not yet report regenerated experimental results. Any future result table should be produced from the scenario-adapter split rather than the deleted deterministic-only split.

Second, LLM-generated natural-language tasks require validation. Generated tasks should be checked for attack-semantic preservation, scenario fit, duplicate wording, oracle leakage, and executable compatibility with the harness.

Third, perturbations must be constrained. A perturbation is useful only if it changes presentation while preserving the private oracle. Invalid perturbations can accidentally change the attack itself.

Fourth, a complete benchmark should include benign controls and utility metrics. Adversarial-only ASR is insufficient for evaluating safety-utility trade-offs.

## 9 Conclusion

CardDiffBench studies a concrete A2A security surface: how hosts interpret AgentCard control-plane state while executing natural user tasks. This revised draft aligns the benchmark generation method with the A2ASecBench scenario-adapter approach. Natural-language tasks are generated from attack vectors and scenario specifications, while AgentCard perturbations are retained as an optional oracle-preserving layer.

The next step is implementation and validation of the scenario-adapted split: generate task banks, attach controlled AgentCard differentials, add matched benign controls, and rerun experiments under the new protocol. Old deterministic-only method claims and pilot result tables have been removed from this draft.

## Appendix A Prompt Set

The current prompt appendix is maintained as a separate draft file:
`paper_drafts/CardDiffBench_prompt_appendix.md`. It contains the CardDiffBench
scenario adapter prompt, strict JSON system contract, attack-vector input
blocks, scenario-specification input blocks, seed examples, protocol-state
perturbation contract, LLM-backed Host decision prompt, and an optional hardened
Host prompt for future mitigation experiments.

## Draft References To Verify

1. A2A Project. Agent-to-Agent Protocol documentation and samples. 2025.
2. Li, T., Chu, C., Zheng, Y., Zhang, B., Gong, N. Z., and Xiao, C. A2ASecBench: A Protocol-Aware Security Benchmark for Agent-to-Agent Multi-Agent Systems. ICLR 2026.
3. Askell et al. Work on harmlessness and helpfulness trade-offs. 2021. [Details needed.]
4. Recent work on multi-agent system security, prompt injection, cascading injection, and agent communication attacks. [Details needed.]

## Claim-Evidence Map

| Claim | Evidence | Status |
| --- | --- | --- |
| AgentCard state differentials are a meaningful A2A control-plane security surface. | Threat model and executable harness design. | Method claim; needs regenerated results. |
| Scenario adaptation should be the primary task-generation method. | Aligned with A2ASecBench generation structure. | Method design. |
| Perturbations can extend scenario-adapted tasks. | Existing adapter can vary AgentCard surfaces while preserving oracles. | Implementation scaffold exists; needs validation under revised pipeline. |
| Current benchmark has final ASR findings. | Old result tables removed. | Not claimed in this draft. |
