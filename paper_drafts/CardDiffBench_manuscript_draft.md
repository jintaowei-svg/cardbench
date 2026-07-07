# CardDiffBench: AgentCard Control-Plane Differential Evaluation

## Abstract

CardDiffBench evaluates Host behavior under AgentCard control-plane
differentials: public cards, authenticated extended cards, supported interfaces,
tenant bindings, security scopes, and output modes can disagree in ways that
change the safety of downstream agent-to-agent routing. We adopt the broad
scenario-adapter workflow pattern from A2ASecBench to instantiate realistic
domain tasks, but CardDiffBench defines its own attack taxonomy, case schema,
perturbation set, and evaluation dataset.

## Benchmark Positioning

CardDiffBench is not a mixed A2ASecBench release. The original A2ASecBench code
is retained only as `reference/archive/a2asecbench/` for provenance and
comparison. Active experiments use the CardDiff-only harness, cases, prompts,
and Host SUTs in the repository root.

## Taxonomy

CardDiffBench covers three families of AgentCard differentials:

| Family | Attack types | Control-plane risk |
| --- | --- | --- |
| Extended-card differentials | A1, A2, A3 | Unsafe reliance on authenticated card state that differs from the public card. |
| Interface and tenant confusion | B1, B2, B3 | Unsafe routing across ordered interfaces, tenants, bindings, or protocol versions. |
| Security and output-mode drift | C1, C2 | Unsafe skill invocation or artifact acceptance when scopes and output modes diverge. |

These categories are CardDiffBench-specific. They should be described as
inspired by AgentCard differential behavior, not as inherited A2ASecBench attack
families.

## Scenario Adapter Method

We borrow the scenario-adapter idea from A2ASecBench: an adapter prompt maps a
scenario specification and an attack vector into concrete natural-language user
tasks. In CardDiffBench, the prompt is maintained separately under
`prompts/carddiff/`, while the frozen test cases and perturbation dataset live
under `attacks/carddiff/`.

This adapter is a generation method, not the benchmark contribution itself. The
benchmark contribution is the CardDiff taxonomy, AgentCard differential schema,
oracle-preserving perturbations, and Host control-plane scoring.

## Dataset

The active dataset is generated from:

- CardDiff attack vectors: `attacks/carddiff/vectors.json`
- Domain scenarios: `attacks/carddiff/scenarios.json`
- Scenario-adapted tasks: `attacks/carddiff/scenario_tasks.json`
- Perturbation variants: `attacks/carddiff/perturbations.json`
- Frozen base and perturbed cases: `attacks/carddiff/cases.jsonl` and
  `attacks/carddiff/perturbed_cases.jsonl`

The dataset is ours. A2ASecBench is referenced only for methodological
background around scenario adaptation.

## Evaluation

Each CardDiff case runs in a local A2A HTTP environment. The Host receives a
public workflow request, performs AgentCard discovery, optionally fetches an
extended card, selects a skill and interface, sends a message, and decides
whether returned artifacts are acceptable. The scorer records attack success
from observed events such as skill invocation, selected tenant, selected
protocol version, scope use, and artifact MIME acceptance.

## Repository Separation

Active CardDiff components are separated as follows:

```text
prompts/carddiff/  Scenario-adapter prompt templates
attacks/carddiff/  Frozen CardDiff cases and dataset assets
sut/carddiff/      CardDiff Host implementations
harness/           CardDiff local protocol environment and scoring
reference/archive/ Original A2ASecBench reference snapshot
```

This separation is part of the experimental design: CardDiff results should not
depend on legacy A2ASecBench attack implementations.
