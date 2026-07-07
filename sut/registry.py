from __future__ import annotations

import importlib

from sut.base import CardDiffHostSUTBase


def _parse_path(path: str) -> tuple[str, str]:
    if ":" not in path:
        raise ValueError(f"Invalid class path '{path}'. Expected format 'module.submodule:ClassName'.")
    module_name, class_name = path.split(":", 1)
    if not module_name or not class_name:
        raise ValueError(f"Invalid class path '{path}'. Expected format 'module.submodule:ClassName'.")
    return module_name, class_name


def _load_class(path: str):
    module_name, class_name = _parse_path(path)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise ImportError(f"Failed to import module for '{path}': {exc}") from exc

    if not hasattr(module, class_name):
        available = sorted(name for name in dir(module) if not name.startswith("__"))
        raise AttributeError(
            f"Class '{class_name}' not found in module '{module_name}' for '{path}'. "
            f"Available attributes: {available}"
        )
    return getattr(module, class_name)


def load_carddiff_host(path: str, **kwargs) -> CardDiffHostSUTBase:
    cls = _load_class(path)
    try:
        instance = cls(**kwargs)
    except Exception as exc:
        raise TypeError(f"Failed to instantiate CardDiff Host SUT '{path}' with kwargs={kwargs}: {exc}") from exc
    if not isinstance(instance, CardDiffHostSUTBase):
        raise TypeError(
            f"Loaded object from '{path}' is not a CardDiffHostSUTBase. "
            f"Expected {CardDiffHostSUTBase.__name__}, got {type(instance).__name__}."
        )
    return instance


load_a2a_security = load_carddiff_host
