from __future__ import annotations

import subprocess
import sys


def main() -> int:
    """Run the project's local validation checks."""
    commands = [
        [sys.executable, "-m", "pytest", "-q"],
    ]

    for command in commands:
        print(f"\nRunning: {' '.join(command)}")
        result = subprocess.run(command, check=False)

        if result.returncode != 0:
            print("\nValidation failed.")
            return result.returncode

    print("\nAll validation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())