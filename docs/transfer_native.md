# Protocol-native transferability experiment

The experiment compares the completed Official A2A main run against native ANP
and NLIP execution. It never projects AgentCard discovery fields into another
protocol and never treats a generic function call or HTTP wrapper as a transfer
target.

## Frozen applicability

| Protocol | A1 | A2 | A3 | B1 | B3 | C1 | C2 |
|---|---|---|---|---|---|---|---|
| Official A2A | main only | yes | yes | yes | yes | yes | yes |
| ANP | N/A | yes | yes | yes | yes | yes | N/A |
| NLIP | N/A | N/A | yes | N/A | N/A | yes | yes |

The local audit verifies the pinned ANP 0.8.8 discovery/server path for A2.
ANP C2 is N/A because no native result/attachment MIME object was verified.
NLIP 0.1.2 exposes message formats, conversation tokens, `NLIP_Session`, and
`NLIP_Application`, but its maintained Python client is HTTPX+JSON only. The
WebSocket binary+CBOR and WebSocket text+JSON pair required by B3 is therefore
N/A.

## Build and preflight

```powershell
python scripts/audit_native_support.py
python scripts/build_transfer_native_cases.py
python scripts/extract_official_a2a_reference.py
python -m pytest tests/transfer_native tests/transfer
```

Install the pinned dependencies in `constraints/transfer-native.txt`. The NLIP
client currently has no PyPI release, so both the constraint file and the
`transfer-native` project extra pin audited upstream commit
`b91edb72a387882ecdc912d5949e707d4727b203`.

If GitHub smart-HTTP clone is blocked but codeload works, install the PyPI
packages first and then install the pinned NLIP client archive without resolving
its broken local-path dependency:

```powershell
$env:HTTP_PROXY="http://127.0.0.1:7897"
$env:HTTPS_PROXY="http://127.0.0.1:7897"
python -m pip install "anp[api]==0.8.8" "nlip_sdk==0.1.2" "nlip_server==0.1.2"
python -m pip install --no-deps "https://codeload.github.com/nlip-project/nlip_client/zip/b91edb72a387882ecdc912d5949e707d4727b203"
```

ANP formal runs also require trial identities through these environment
variables for each label used by the manifest:

```text
CARDDIFF_ANP_NORMAL_USER_DID_DOCUMENT
CARDDIFF_ANP_NORMAL_USER_PRIVATE_KEY
CARDDIFF_ANP_PRIVILEGED_USER_DID_DOCUMENT
CARDDIFF_ANP_PRIVILEGED_USER_PRIVATE_KEY
```

Each trial starts a fresh deterministic native OpenANP peer automatically.
`CARDDIFF_ANP_PEER_BASE_URL` may instead point at an externally managed peer.
NLIP likewise starts a fresh official `nlip_server` application per trial;
`CARDDIFF_NLIP_PEER_URL` overrides it with an external deterministic peer.

## Formal runs

```powershell
python -m harness.transfer_native.runner configs/transfer_native/anp.yaml --output results/transfer_native/anp/details.jsonl
python -m harness.transfer_native.runner configs/transfer_native/nlip.yaml --output results/transfer_native/nlip/details.jsonl
```

Only infrastructure failures may be rerun. Preserve the original record and
build an exact case-ID replacement manifest; model refusal, safe decisions,
valid parse failures, server authorization rejection, and unsuccessful oracle
judgments are trial outcomes, not rerun candidates.

## Aggregate

```powershell
python scripts/aggregate_transfer_native.py `
  --official-a2a results/transfer_native/official_a2a_reference/details.jsonl `
  --anp results/transfer_native/anp/details.jsonl `
  --nlip results/transfer_native/nlip/details.jsonl
python scripts/build_transfer_native_integrity.py
python scripts/consolidate_paper_results.py
```
