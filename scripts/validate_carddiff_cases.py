from __future__ import annotations

import argparse
from collections import Counter
import importlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CASES_PATH = ROOT / "attacks" / "carddiff" / "cases.jsonl"
PERTURBED_CASES_PATH = ROOT / "attacks" / "carddiff" / "perturbed_cases.jsonl"
PERTURBATIONS_PATH = ROOT / "attacks" / "carddiff" / "perturbations.json"
SCENARIO_TASKS_PATH = ROOT / "attacks" / "carddiff" / "scenario_tasks.json"
ATTACK_TYPES = {"A1", "A2", "A3", "B1", "B2", "C1", "C2"}
SCENARIOS = {"travel", "healthcare", "finance"}
FORBIDDEN_PUBLIC_TOKENS = (
    "oracle",
    "attack_success",
    "sensitive_skill_id",
    "drift_url",
    "attacker_preferred_url",
    "required_scope",
    "CARDDIFF_A",
    "CARDDIFF_B",
    "CARDDIFF_C",
    "supportsAuthenticatedExtendedCard",
    "securityRequirements",
)


def load_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_perturbation_variants(path: Path = PERTURBATIONS_PATH) -> set[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(variant["variant_id"]) for variant in payload["variants"]}


def load_scenario_task_ids(path: Path = SCENARIO_TASKS_PATH) -> dict[tuple[str, str], set[str]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    task_ids: dict[tuple[str, str], set[str]] = {}
    for cell in payload.get("cells", []):
        attack_type = str(cell.get("attack_type", ""))
        scenario = str(cell.get("scenario", ""))
        tasks = cell.get("tasks", [])
        if not attack_type or not scenario or not isinstance(tasks, list):
            continue
        ids = {
            str(task.get("task_id", "")).strip()
            for task in tasks
            if isinstance(task, dict) and str(task.get("task_id", "")).strip()
        }
        if ids:
            task_ids[(attack_type, scenario)] = ids
    return task_ids


def validate_cases(
    cases: list[dict[str, Any]],
    *,
    expected_count: int = 24,
    expected_variants: set[str] | None = None,
    expected_task_ids: dict[tuple[str, str], set[str]] | None = None,
    import_module: str = "attacks.instances.carddiff",
    class_prefix: str = "CardDiff",
) -> None:
    if len(cases) != expected_count:
        raise ValueError(f"CardDiff must contain {expected_count} cases, got {len(cases)}")
    case_ids = [case["case_id"] for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("CardDiff case_id values must be unique")

    expected_task_ids = expected_task_ids or {}
    if expected_variants is None:
        coverage = {
            (
                case["attack_type"],
                case["scenario"],
                _scenario_task_key(case),
            )
            for case in cases
        }
        expected = {
            (attack_type, scenario, task_id)
            for attack_type in ATTACK_TYPES
            for scenario in SCENARIOS
            for task_id in _expected_task_ids(expected_task_ids, attack_type, scenario)
        }
    else:
        coverage = {
            (
                case["attack_type"],
                case["scenario"],
                _scenario_task_key(case),
                case["perturbation"]["variant_id"],
            )
            for case in cases
        }
        expected = {
            (attack_type, scenario, task_id, variant)
            for attack_type in ATTACK_TYPES
            for scenario in SCENARIOS
            for task_id in _expected_task_ids(expected_task_ids, attack_type, scenario)
            for variant in expected_variants
        }
    if coverage != expected:
        missing = sorted(expected - coverage)
        extra = sorted(coverage - expected)
        raise ValueError(f"CardDiff coverage mismatch missing={missing} extra={extra}")

    attack_counts = Counter(case["attack_type"] for case in cases)
    scenario_counts = Counter(case["scenario"] for case in cases)
    variants_per_cell = len(expected_variants) if expected_variants is not None else 1
    expected_attack_counts = {
        attack_type: sum(
            len(_expected_task_ids(expected_task_ids, attack_type, scenario))
            for scenario in SCENARIOS
        )
        * variants_per_cell
        for attack_type in ATTACK_TYPES
    }
    expected_scenario_counts = {
        scenario: sum(
            len(_expected_task_ids(expected_task_ids, attack_type, scenario))
            for attack_type in ATTACK_TYPES
        )
        * variants_per_cell
        for scenario in SCENARIOS
    }
    if (
        set(attack_counts) != ATTACK_TYPES
        or any(count != expected_attack_counts[attack] for attack, count in attack_counts.items())
    ):
        raise ValueError(
            f"CardDiff attack counts mismatch expected={expected_attack_counts} got={dict(attack_counts)}"
        )
    if (
        set(scenario_counts) != SCENARIOS
        or any(count != expected_scenario_counts[scenario] for scenario, count in scenario_counts.items())
    ):
        raise ValueError(
            f"CardDiff scenario counts mismatch expected={expected_scenario_counts} got={dict(scenario_counts)}"
        )

    for index, case in enumerate(cases, start=1):
        _validate_case(case)
        _validate_importable(case, index, import_module, class_prefix)


def _validate_case(case: dict[str, Any]) -> None:
    if case.get("schema_version") != "carddiff-a2a-v1":
        raise ValueError(f"{case.get('case_id')} has invalid schema_version")
    if case.get("attack_id") != "CARDDIFF":
        raise ValueError(f"{case.get('case_id')} has invalid attack_id")
    if case.get("attack_type") not in ATTACK_TYPES:
        raise ValueError(f"{case.get('case_id')} has invalid attack_type")
    if case.get("scenario") not in SCENARIOS:
        raise ValueError(f"{case.get('case_id')} has invalid scenario")

    public = case.get("public")
    if not isinstance(public, dict):
        raise ValueError(f"{case['case_id']} public payload must be a mapping")
    public_text = json.dumps(public, ensure_ascii=True)
    leaks = [token for token in FORBIDDEN_PUBLIC_TOKENS if token in public_text]
    if leaks:
        raise ValueError(f"{case['case_id']} public payload leaks private tokens: {leaks}")
    if public.get("base_url") != "{{base_url}}":
        raise ValueError(f"{case['case_id']} public base_url must be a runtime placeholder")

    agent = case.get("agent")
    if not isinstance(agent, dict):
        raise ValueError(f"{case['case_id']} agent metadata must be a mapping")
    cards = [agent.get("public_card"), *agent.get("extended_cards", {}).values()]
    for card in cards:
        _validate_agent_card(case["case_id"], card)
        _assert_no_legacy_fields(case["case_id"], card)

    response = agent.get("response", {})
    artifact = response.get("artifact", {})
    if not artifact.get("artifactId") or not isinstance(artifact.get("parts"), list):
        raise ValueError(f"{case['case_id']} response artifact must contain artifactId and parts")


def _scenario_task_key(case: dict[str, Any]) -> str:
    generation = case.get("generation", {})
    if isinstance(generation, dict):
        task_id = generation.get("scenario_task_id")
        if task_id:
            return str(task_id)
    return "__template_fallback__"


def _expected_task_ids(
    task_ids: dict[tuple[str, str], set[str]],
    attack_type: str,
    scenario: str,
) -> set[str]:
    return task_ids.get((attack_type, scenario), {"__template_fallback__"})


def _expected_count(
    task_ids: dict[tuple[str, str], set[str]],
    *,
    variant_count: int = 1,
) -> int:
    return sum(
        len(_expected_task_ids(task_ids, attack_type, scenario)) * variant_count
        for attack_type in ATTACK_TYPES
        for scenario in SCENARIOS
    )


def _parse_variant_ids(text: str | None) -> set[str] | None:
    if not text:
        return None
    return {
        item.strip().zfill(3) if item.strip().isdigit() else item.strip()
        for item in text.split(",")
        if item.strip()
    }


def _validate_agent_card(case_id: str, card: Any) -> None:
    if not isinstance(card, dict):
        raise ValueError(f"{case_id} AgentCard must be a mapping")
    required = {
        "name",
        "description",
        "version",
        "url",
        "capabilities",
        "supportedInterfaces",
        "securitySchemes",
        "security",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
    }
    missing = required - set(card)
    if missing:
        raise ValueError(f"{case_id} AgentCard missing fields: {sorted(missing)}")
    if card.get("capabilities", {}).get("extendedAgentCard") is not True:
        raise ValueError(f"{case_id} AgentCard must advertise capabilities.extendedAgentCard=true")
    if not isinstance(card.get("supportedInterfaces"), list) or not card["supportedInterfaces"]:
        raise ValueError(f"{case_id} AgentCard must contain supportedInterfaces")
    for interface in card["supportedInterfaces"]:
        for key in ("url", "protocolBinding", "protocolVersion", "transport", "tenant"):
            if key not in interface:
                raise ValueError(f"{case_id} AgentInterface missing {key}")
        if not str(interface["url"]).startswith("{{base_url}}"):
            raise ValueError(f"{case_id} AgentInterface URL must use runtime base_url placeholder")
    for key in ("securitySchemes", "security"):
        if key not in card:
            raise ValueError(f"{case_id} AgentCard missing {key}")
    if not isinstance(card.get("skills"), list) or not card["skills"]:
        raise ValueError(f"{case_id} AgentCard must contain skills")


def _assert_no_legacy_fields(case_id: str, value: Any) -> None:
    text = json.dumps(value, ensure_ascii=True)
    for token in ("supportsAuthenticatedExtendedCard", "securityRequirements"):
        if token in text:
            raise ValueError(f"{case_id} uses legacy/non-CardDiff field {token}")


def _validate_importable(
    case: dict[str, Any],
    index: int,
    import_module: str,
    class_prefix: str,
) -> None:
    module = importlib.import_module(import_module)
    class_name = f"CardDiff{index:03d}"
    if class_prefix != "CardDiff":
        class_name = f"{class_prefix}{index:03d}"
    instance = getattr(module, class_name)()
    if instance.case_id != case["case_id"]:
        raise ValueError(f"{class_name} did not instantiate {case['case_id']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate CardDiff base and perturbed cases.")
    parser.add_argument(
        "--variant-ids",
        default=None,
        help="Comma-separated perturbation variant IDs expected in perturbed_cases.jsonl.",
    )
    args = parser.parse_args()

    expected_task_ids = load_scenario_task_ids()
    cases = load_cases()
    validate_cases(
        cases,
        expected_count=_expected_count(expected_task_ids),
        expected_task_ids=expected_task_ids,
    )
    perturbed_cases = load_cases(PERTURBED_CASES_PATH)
    selected_variants = _parse_variant_ids(args.variant_ids)
    all_variants = load_perturbation_variants()
    expected_variants = selected_variants or {"001", "002", "003"}
    unknown = expected_variants - all_variants
    if unknown:
        raise ValueError(f"Unknown CardDiff perturbation variants: {sorted(unknown)}")
    validate_cases(
        perturbed_cases,
        expected_count=_expected_count(expected_task_ids, variant_count=len(expected_variants)),
        expected_variants=expected_variants,
        expected_task_ids=expected_task_ids,
        import_module="attacks.instances.carddiff_perturbed",
        class_prefix="CardDiffPerturbed",
    )
    print("CardDiff base and perturbed case validation passed")


if __name__ == "__main__":
    main()
