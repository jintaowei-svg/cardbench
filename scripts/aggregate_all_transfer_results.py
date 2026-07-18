from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SUMMARY = ROOT / "results/transfer_native/aggregate/summary.json"
EXTENSION_SUMMARY = ROOT / "results/transfer_extension/aggregate/summary.json"
APPLICABILITY = ROOT / "attacks/carddiff/transfer_extension/applicability.json"
NATIVE_APPLICABILITY = ROOT / "attacks/carddiff/transfer_native/applicability.json"
OUTPUT = ROOT / "results/transfer_all"
LATEX_OUTPUT = ROOT / "paper_drafts/CardDiffBench_AAAI2027_Overleaf/tables/transferability.tex"

PANELS = {
    "protocol_transfer": ("ANP", "NLIP"),
    "ecosystem_framework_transfer": ("AGNTCY", "AutoGen", "LangGraph"),
}
DISPLAY_ATTACKS = ("A1", "A2", "A3", "B1", "B2", "C1", "C2")
TARGET_KEYS = {
    "ANP": "anp",
    "NLIP": "nlip",
    "AGNTCY": "agntcy",
    "AutoGen": "autogen",
    "LangGraph": "langgraph",
}
RERUN_REQUIRED = {
    ("ANP", "A3"),
    ("NLIP", "A3"),
    ("NLIP", "C1"),
    ("AutoGen", "A3"),
}


def _cell(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "reported",
        "trials": int(row["trials"]),
        "judged": int(row["judged"]),
        "successes": int(row["successes"]),
        "asr_planned": float(row.get("asr_planned", row["asr"])),
        "asr_judged": (
            float(row["asr_judged"]) if row.get("asr_judged") is not None else None
        ),
        "completion_rate": float(row["completion_rate"]),
    }


def _available_rows(
    native: dict[str, Any], extension: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in native["by_attack"]:
        label = {"anp": "ANP", "nlip": "NLIP"}.get(str(row["protocol"]))
        if label:
            rows[(label, str(row["attack"]))] = _cell(row)
    extension_groups = {
        "AGNTCY": extension.get("ecosystem_native", {}).get("agntcy", []),
        "AutoGen": extension.get("framework_native", {}).get("autogen", []),
        "LangGraph": extension.get("framework_native", {}).get("langgraph", []),
    }
    for label, values in extension_groups.items():
        for row in values:
            rows[(label, str(row["attack"]))] = _cell(row)
    return rows


def _applicable(target: str, attack: str, native: dict[str, Any], extension: dict[str, Any]) -> bool:
    key = TARGET_KEYS[target]
    matrix = native if target in {"ANP", "NLIP"} else extension
    return matrix.get(key, {}).get(attack) == "applicable"


def _latex_cell(cell: dict[str, Any]) -> str:
    if cell["status"] == "not_applicable":
        return "N/A"
    if cell["status"] == "pending":
        return "Pending"
    return (
        f'{cell["asr_planned"] * 100:.2f}\\% '
        f'({cell["completion_rate"] * 100:.2f}\\%)'
        + (r"$^\dagger$" if cell.get("rerun_required") else "")
    )


def aggregate() -> dict[str, Any]:
    native_summary = json.loads(NATIVE_SUMMARY.read_text(encoding="utf-8"))
    extension_summary = json.loads(EXTENSION_SUMMARY.read_text(encoding="utf-8"))
    native_applicability = json.loads(NATIVE_APPLICABILITY.read_text(encoding="utf-8"))
    extension_applicability = json.loads(APPLICABILITY.read_text(encoding="utf-8"))
    available = _available_rows(native_summary, extension_summary)

    panels: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    flat_rows: list[dict[str, Any]] = []
    for panel, targets in PANELS.items():
        panels[panel] = {}
        for attack in DISPLAY_ATTACKS:
            panels[panel][attack] = {}
            for target in targets:
                cell = available.get((target, attack))
                if cell is None:
                    status = (
                        "pending"
                        if _applicable(
                            target,
                            attack,
                            native_applicability,
                            extension_applicability,
                        )
                        else "not_applicable"
                    )
                    cell = {
                        "status": status,
                        "trials": None,
                        "judged": None,
                        "successes": None,
                        "asr_planned": None,
                        "asr_judged": None,
                        "completion_rate": None,
                    }
                panels[panel][attack][target] = cell
                cell["rerun_required"] = (
                    cell["status"] == "reported"
                    and (target, attack) in RERUN_REQUIRED
                )
                flat_rows.append(
                    {"panel": panel, "attack": attack, "target": target, **cell}
                )

    summary = {
        "schema_version": "carddiff-transfer-all-v2",
        "primary_metric": "asr_planned",
        "secondary_metrics": ["asr_judged", "completion_rate"],
        "attack_identifiers": list(DISPLAY_ATTACKS),
        "panels": panels,
        "notes": [
            "All local, generated, and paper artifacts use the canonical attack identifiers.",
            "AutoGen B1 was removed and is represented as N/A, not as a zero result.",
            "Each reported cell is ASR over planned trials, followed by completion rate in parentheses.",
            "Pending denotes an applicable target/attack whose formal run has not been executed.",
            "A dagger marks a legacy result that must be rerun after an implementation-semantic revision.",
        ],
    }

    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with (OUTPUT / "by_attack.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(flat_rows[0]))
        writer.writeheader()
        writer.writerows(flat_rows)

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\small",
        r"\setlength{\tabcolsep}{7pt}",
        r"\renewcommand{\arraystretch}{1.08}",
        r"\textbf{Panel A: Protocol transfer}\\[2pt]",
        r"\begin{tabular}{lcc}",
        r"\toprule",
        r"Attack & ANP & NLIP \\",
        r"\midrule",
    ]
    for attack in DISPLAY_ATTACKS:
        values = " & ".join(
            _latex_cell(panels["protocol_transfer"][attack][target])
            for target in PANELS["protocol_transfer"]
        )
        lines.append("{} & {} \\\\".format(attack, values))
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\vspace{5pt}",
            r"\textbf{Panel B: Ecosystem and framework transfer}\\[2pt]",
            r"\begin{tabular}{lccc}",
            r"\toprule",
            r"Attack & AGNTCY & AutoGen & LangGraph \\",
            r"\midrule",
        ]
    )
    for attack in DISPLAY_ATTACKS:
        values = " & ".join(
            _latex_cell(panels["ecosystem_framework_transfer"][attack][target])
            for target in PANELS["ecosystem_framework_transfer"]
        )
        lines.append("{} & {} \\\\".format(attack, values))
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\caption{Transferability results. Each reported cell gives planned-trial ASR, with completion rate in parentheses. N/A denotes no verified native counterpart; Pending denotes an applicable formal run not yet executed. A dagger marks a legacy result requiring rerun after an implementation-semantic revision.}",
            r"\label{tab:transferability}",
            r"\end{table*}",
            "",
        ]
    )
    LATEX_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    LATEX_OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(aggregate(), ensure_ascii=False, indent=2))
