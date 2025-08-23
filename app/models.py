# Re-export User model from centralized CreateDB, with repo-root path guard for local runs
import os, sys
_current_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.abspath(os.path.join(_current_dir, '..', '..'))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
from CreateDB.models import User  # noqa: F401