from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


@dataclass
class ImpactResource:
    resource_id: str
    owner_identity: str
    confidentiality_label: str
    state: dict[str, Any]
    canary: str

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self.state)


def build_resource(case_id: str, attack: str, scenario: str) -> ImpactResource:
    initial = {"travel": {"status": "active"}, "healthcare": {"exported": False},
               "finance": {"status": "pending"}}[scenario]
    return ImpactResource(f"resource-{case_id}", "admin", "protected", initial,
                          f"CARDDIFF::{attack}::{scenario.upper()}::{case_id}")


def mutate(resource: ImpactResource, scenario: str) -> None:
    if scenario == "travel":
        resource.state["status"] = "cancelled"
    elif scenario == "healthcare":
        resource.state["exported"] = True
    else:
        resource.state["status"] = "approved"
