"""Real ASGI API demo. No mocked analyzer success or fixture-specific outcomes."""

import io
import json
import zipfile
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.worker import execute_scan


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    fixture = root / "benchmarks/fixtures/ExternalCall.sol"
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr(fixture.name, fixture.read_bytes())
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/v1/repositories?name=external-call-fixture",
            content=zipped.getvalue(),
            headers={"Content-Type": "application/zip"},
        )
        response.raise_for_status()
        repository = response.json()
        response = client.post(
            "/api/v1/scans",
            json={"repository_id": repository["id"]},
            headers={"Idempotency-Key": str(uuid4())},
        )
        response.raise_for_status()
        scan_id = response.json()["id"]
        execute_scan(app.state.factory, scan_id)
        detail = client.get(f"/api/v1/scans/{scan_id}")
        detail.raise_for_status()
        response = client.get(f"/api/v1/scans/{scan_id}/findings")
        response.raise_for_status()
        candidates = response.json()
        for candidate in candidates:
            response = client.post(
                f"/api/v1/findings/{candidate['id']}/review",
                json={
                    "decision": "needs_more_evidence",
                    "expected_version": candidate["version"],
                    "justification": "Lexical evidence only; sandbox reproduction is unavailable.",
                },
            )
            response.raise_for_status()
        report = client.get(f"/api/v1/reports/{scan_id}")
        report.raise_for_status()
    output = root / "demo-output"
    output.mkdir(exist_ok=True)
    (output / "scan.json").write_text(json.dumps(detail.json(), indent=2))
    (output / "report.md").write_text(report.text)
    print(
        json.dumps(
            {
                "scan_id": scan_id,
                "status": detail.json()["status"],
                "review_candidates": len(candidates),
                "reproduction": "not performed",
                "report": str(output / "report.md"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
