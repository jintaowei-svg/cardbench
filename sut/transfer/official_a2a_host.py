from __future__ import annotations

from sut.transfer.base import TransferHostBase
from sut.transfer.official_a2a_protocol import SDK_AVAILABLE


class OfficialSDKCardDiffHostSUT(TransferHostBase):
    """Official A2A SDK transfer target with an isolated protocol adapter."""

    transfer_target = "official_a2a"
    framework_version = "a2a-sdk" if SDK_AVAILABLE else "a2a-sdk-unavailable"

    def _record_native_call(self, env, interface, skill, step_index):
        if hasattr(env, "record_native_event"):
            env.record_native_event("a2a_sdk_message_sent", {"step_index": step_index, "selected_url": interface.get("url"), "skill_id": skill.get("id"), "sdk_available": SDK_AVAILABLE})
