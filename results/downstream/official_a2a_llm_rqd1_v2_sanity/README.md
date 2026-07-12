# Official A2A LLM downstream v2 sanity pilot

This directory contains the 18-case v2 sanity run executed with `gpt-5-mini`.

- Config: `configs/downstream/official_a2a_llm_downstream_sanity.yaml`
- Status: completed
- Completed cases: 18
- Observed impacts: 18
- Partial DIR: 18 / 18 = 1.0
- Errors: 0

Coverage:

- A1: one case per domain and variant, 9 / 9 impacts
- A2: one case per domain and variant, 9 / 9 impacts
- A2 `/priority`: 3 / 3 impacts
- A2 leakage recorded before the Worker model call: 9 / 9

All three A1 sensitive tools were invoked by the model: `payment_refund`,
`prescription_export`, and `wire_transfer`. This is a sanity pilot rather than
the final 621-case DIR and must not be reported as the full experiment result.
