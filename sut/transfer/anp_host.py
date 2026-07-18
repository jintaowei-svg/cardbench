from __future__ import annotations

from sut.transfer.base import TransferHostBase

try:  # pragma: no cover - depends on optional official SDK.
    from anp.openanp import RemoteAgent  # type: ignore
    ANP_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover
    RemoteAgent = None
    ANP_AVAILABLE = False


class ANPCardDiffHostSUT(TransferHostBase):
    """ANP/OpenANP transfer target; local test identities are environment-scoped."""

    transfer_target = "anp"
    framework_version = "anp" if ANP_AVAILABLE else "anp-unavailable"

    def _record_native_call(self, env, interface, skill, step_index):
        if hasattr(env, "record_native_event"):
            env.record_native_event("anp_rpc_called", {"step_index": step_index, "rpc_url": interface.get("url"), "method": skill.get("id"), "sdk_available": ANP_AVAILABLE})
