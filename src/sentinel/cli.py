import argparse
import os

from sentinel.db import sessions
from sentinel.worker import execute_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Single-process Sentinel worker")
    parser.add_argument("scan_id")
    args = parser.parse_args()
    factory = sessions(os.getenv("SENTINEL_DATABASE_URL", "sqlite:///sentinel.db"))
    execute_scan(factory, args.scan_id)


if __name__ == "__main__":
    main()
