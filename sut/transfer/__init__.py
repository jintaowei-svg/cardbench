"""Official A2A implementation retained by the main experiment."""

__all__ = ["OfficialSDKCardDiffHostSUT"]


def __getattr__(name: str):
    if name == "OfficialSDKCardDiffHostSUT":
        from sut.transfer.official_a2a_host import OfficialSDKCardDiffHostSUT
        return OfficialSDKCardDiffHostSUT
    raise AttributeError(name)
