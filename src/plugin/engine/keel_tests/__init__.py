"""Self-tests of the Keel engine.

Every test runs git with an empty global and system config: the owner's `core.hooksPath`,
`commit.gpgsign`, aliases or templates must not change the verdict (and CI has none of them).
"""
import atexit
import os
import tempfile

_EMPTY_CONFIG = tempfile.NamedTemporaryFile("w", prefix="keel-gitconfig-", suffix=".cfg", delete=False)
_EMPTY_CONFIG.write("[init]\n\tdefaultBranch = main\n")  # без [user]: CI-раннер теж без імені, і тест має це бачити
_EMPTY_CONFIG.close()
os.environ["GIT_CONFIG_GLOBAL"] = _EMPTY_CONFIG.name
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
for _name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "KEEL_VAULT",
              "KEEL_ALLOW_SECRET"):
    os.environ.pop(_name, None)
atexit.register(lambda: os.path.exists(_EMPTY_CONFIG.name) and os.unlink(_EMPTY_CONFIG.name))
