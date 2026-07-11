# Official A2A SDK-Backed Transfer Target

The `official_a2a` target uses the pinned a2a-sdk 0.3.x stack end to end. Public
discovery calls `A2ACardResolver.get_agent_card`; the Host projects the selected
interface into an SDK `AgentCard`, constructs an SDK `Message`/`Part`, and sends
it with a client created by `ClientFactory`. The in-process peer is an
`A2AStarletteApplication` using `DefaultRequestHandler`, `AgentExecutor`, and
`InMemoryTaskStore`, reached through HTTPX `ASGITransport`.

CardDiff fields that a2a-sdk 0.3.x does not represent natively are carried by a
hash-bound companion control-plane document. These include ordered alternative
interfaces, identity-specific extended-card state, tenant selection, per-skill
security requirements, binding/version alternatives, and output-acceptance
context. The Host, not the Environment, retains all selection and cache policy.

The peer returns the benchmark task/artifact envelope in an SDK `DataPart`.
This avoids relying on unstable Task/Artifact APIs while ensuring both request
and response traverse official SDK models and handlers.

Install and test with:

```bash
pip install -e ".[dev]" -c constraints/a2a-sdk-l3.txt
python -m pytest tests/transfer
```

There is deliberately no requests-based fallback. Missing or incompatible SDK
imports stop the official target immediately.
