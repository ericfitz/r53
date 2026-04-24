"""Standalone cleanup script for integration-test records.

Invoke with: uv run tests/integration/cleanup_script.py

Loads the same .r53-itest.toml that the test suite uses, then sweeps
any records matching the r53-itest- prefix in the configured zone.
Useful for recovering from a crashed or Ctrl-C'd test run.
"""

from __future__ import annotations

import logging
import sys

# Allow running as a script: add repo root to sys.path so "tests.integration.*"
# imports resolve.
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.integration.cleanup import sweep  # noqa: E402
from tests.integration.config import ConfigError, load_config  # noqa: E402


def main() -> int:
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
    try:
        config = load_config()
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 1

    deleted = sweep(config)
    if deleted:
        print(f"Deleted {len(deleted)} record(s):")
        for name in deleted:
            print(f"  {name}")
    else:
        print("No r53-itest-* records found to clean up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
