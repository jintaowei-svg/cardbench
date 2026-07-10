from __future__ import annotations

"""Run exactly one paid transfer decision against the configured LLM endpoint."""

import json

from attacks.instances.carddiff_perturbed import CardDiffPerturbed001
from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT


def main() -> None:
    outcome = CardDiffPerturbed001().run(
        OfficialSDKCardDiffHostSUT(model="gpt-5-mini", temperature=0, max_retries=1),
        environment={
            "factory": "harness.transfer.official_a2a_env:OfficialSDKCardDiffEnvironment",
            "kwargs": {"remote_agent_mode": "deterministic"},
        },
    )
    print(json.dumps({"success": outcome.success, "errors": outcome.errors, "metrics": outcome.details["metrics"]}, sort_keys=True))


if __name__ == "__main__":
    main()
