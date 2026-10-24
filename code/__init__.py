"""Ghost Data Still Exists — AI-Powered Deletion Audit Agent.

Root package for audit orchestration, identity resolution, evidence processing,
policy rules evaluation, remediation planning, and output validation.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path
import sys

__version__ = "0.1.0"

# Note: The competition repository requires the package directory to be named 'code'.
# In Python standard library, there is a built-in module also named 'code' (used by pdb/pytest).
# To prevent namespace collision in tools like pytest/pdb that do `import code`,
# we re-export standard library 'code' attributes if available.
_stdlib_code_path = Path(sys.base_prefix) / "Lib" / "code.py"
if not _stdlib_code_path.is_file():
    # Fallback search in sys.path
    for p in sys.path:
        cand = Path(p) / "code.py"
        if cand.is_file() and "site-packages" not in str(cand):
            _stdlib_code_path = cand
            break

if _stdlib_code_path.is_file():
    try:
        _loader = importlib.machinery.SourceFileLoader("_stdlib_code", str(_stdlib_code_path))
        _spec = importlib.util.spec_from_loader("_stdlib_code", _loader)
        if _spec and _spec.loader:
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            for _attr in dir(_mod):
                if not _attr.startswith("__") and _attr not in globals():
                    globals()[_attr] = getattr(_mod, _attr)
    except Exception:
        pass
