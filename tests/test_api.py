from conftest import archive
from sqlalchemy import select

from sentinel.db import AnalyzerRun, AuditEvent, Finding, Repository, Scan
from sentinel.domain import AnalyzerResult
from sentinel.worker import execute_scan


def create_scan(client, key="demo-request-1"):
    response = client.post(
        "/api/v1/repositories?name=fixture",
        content=archive(
            {"A.sol": "contract A { function f() external {require(tx.origin == msg.sender); } }"}
        ),
        headers={"Content-Type": "application/zip"},
    )
    assert response.status_code == 201
    repo = response.json()["id"]
    response = client.post(
        "/api/v1/scans", json={"repository_id": repo}, headers={"Idempotency-Key": key}
    )
    assert response.status_code == 201
    return response.json()["id"], repo


def test_end_to_end_persist_review_report(client):
    scan, repo = create_scan(client)
    factory = client.app.state.factory
    execute_scan(factory, scan)
    detail = client.get(f"/api/v1/scans/{scan}").json()
    assert detail["status"] == "partial"
    assert [r["status"] for r in detail["analyzers"]].count("unavailable") == 2
    finding = client.get(f"/api/v1/scans/{scan}/findings").json()[0]
    assert finding["strength"] == "plausible_unverified"
    body = {
        "decision": "accepted",
        "justification": "Requires manual investigation",
        "expected_version": 1,
    }
    review = client.post(f"/api/v1/findings/{finding['id']}/review", json=body)
    assert review.status_code == 200
    assert review.json()["version"] == 2
    assert client.post(f"/api/v1/findings/{finding['id']}/review", json=body).status_code == 409
    execute_scan(factory, scan)
    report = client.get(f"/api/v1/reports/{scan}").text
    assert detail["revision"] in report
    assert "No executable reproduction" in report
    with factory() as db:
        assert len(list(db.scalars(select(Finding)))) == 1
        assert len(list(db.scalars(select(AnalyzerRun)))) == 3
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "human_review"))
    repeated = client.post(
        "/api/v1/scans", json={"repository_id": repo}, headers={"Idempotency-Key": "demo-request-1"}
    )
    assert repeated.json()["id"] == scan


def test_cross_tenant_and_local_guards(client):
    scan, repo = create_scan(client)
    with client.app.state.factory.begin() as db:
        db.get(Scan, scan).tenant = "other"
        db.get(Repository, repo).tenant = "other"
    for path in (
        f"/api/v1/scans/{scan}",
        f"/api/v1/scans/{scan}/findings",
        f"/api/v1/reports/{scan}",
    ):
        assert client.get(path).status_code == 404
    assert client.get("/api/v1/repositories").json() == []
    assert client.get("/api/v1/scans", headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.get("/api/v1/scans", headers={"Host": "evil.test"}).status_code == 403


def test_cancellation(client):
    scan, _ = create_scan(client)
    assert client.post(f"/api/v1/scans/{scan}/cancel").json()["status"] == "cancelled"
    execute_scan(client.app.state.factory, scan)
    assert client.get(f"/api/v1/scans/{scan}").json()["analyzers"] == []


def test_worker_restart_skips_committed_node(client):
    scan, _ = create_scan(client)
    factory = client.app.state.factory
    execute_scan(factory, scan)
    with factory.begin() as db:
        db.get(Scan, scan).status = "running"
    execute_scan(factory, scan)
    with factory() as db:
        assert len(list(db.scalars(select(AnalyzerRun)))) == 3
        assert len(list(db.scalars(select(Finding)))) == 1


def test_analyzer_failure_never_success(client):
    class Failed:
        tool = "failed"

        def run(self, manifest, snapshot):
            return AnalyzerResult(tool=self.tool, version="test", status="failed", error="build")

    scan, _ = create_scan(client)
    execute_scan(client.app.state.factory, scan, [Failed()])
    assert client.get(f"/api/v1/scans/{scan}").json()["status"] == "failed"


def test_invalid_upload(client):
    assert (
        client.post(
            "/api/v1/repositories?name=x",
            content=b"bad",
            headers={"Content-Type": "application/zip"},
        ).status_code
        == 422
    )
    assert client.get("/api/v1/scans?limit=500").status_code == 422
    assert client.get("/api/v1/health").headers["X-Correlation-ID"]


def test_finding_detail_tenant_guard_and_audit_attribution(client):
    scan, _ = create_scan(client)
    factory = client.app.state.factory
    execute_scan(factory, scan)
    finding = client.get(f"/api/v1/scans/{scan}/findings").json()[0]
    assert client.get(f"/api/v1/findings/{finding['id']}").status_code == 200
    response = client.post(
        f"/api/v1/findings/{finding['id']}/review",
        json={
            "decision": "needs_more_evidence",
            "expected_version": 1,
            "justification": "Static evidence is insufficient.",
        },
    )
    assert response.status_code == 200
    with factory.begin() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "human_review"))
        assert event.actor == "local-demo"
        assert event.created_at is not None
        db.get(Finding, finding["id"]).tenant = "other"
    assert client.get(f"/api/v1/findings/{finding['id']}").status_code == 404
    assert (
        client.post(
            f"/api/v1/findings/{finding['id']}/review",
            json={
                "decision": "accepted",
                "expected_version": 2,
                "justification": "Another tenant must never approve.",
            },
        ).status_code
        == 404
    )


def test_same_origin_browser_requests_are_usable_and_proxy_headers_not_trusted(client):
    response = client.post(
        "/api/v1/repositories?name=browser",
        content=archive({"A.sol": "contract A {}"}),
        headers={"Content-Type": "application/zip", "Origin": "http://127.0.0.1"},
    )
    assert response.status_code == 201
    assert (
        client.get(
            "/api/v1/scans",
            headers={
                "Host": "evil.test",
                "X-Forwarded-Host": "localhost",
                "X-Forwarded-For": "127.0.0.1",
            },
        ).status_code
        == 403
    )
    assert client.get("/api/v1/scans", headers={"Origin": "null"}).status_code == 403


def test_severity_filters_and_pagination(client):
    scan, _ = create_scan(client)
    execute_scan(client.app.state.factory, scan)
    assert len(client.get(f"/api/v1/scans/{scan}/findings?severity=info").json()) == 1
    assert client.get(f"/api/v1/scans/{scan}/findings?severity=critical").json() == []
    assert client.get(f"/api/v1/scans/{scan}/findings?offset=1").json() == []


def test_fatal_interruption_recovers_committed_analyzer_with_new_session_factory(client):
    import pytest

    from sentinel.analysis import LexicalAnalyzer
    from sentinel.db import sessions

    class InterruptedAnalyzer:
        tool = "synthetic-interruption"
        attempts = 0

        def run(self, manifest, snapshot):
            self.attempts += 1
            if self.attempts == 1:
                raise SystemExit("Simulated abrupt worker interruption")
            return AnalyzerResult(
                tool=self.tool, version="synthetic-test-version", status="completed"
            )

    scan, _ = create_scan(client)
    factory = client.app.state.factory
    interrupted = InterruptedAnalyzer()
    with pytest.raises(SystemExit):
        execute_scan(factory, scan, [LexicalAnalyzer(), interrupted])
    with factory() as db:
        committed = db.scalar(select(AnalyzerRun))
        original_id = committed.id
        assert db.get(Scan, scan).status == "running"
    restarted = sessions(str(factory.kw["bind"].url))
    execute_scan(restarted, scan, [LexicalAnalyzer(), interrupted])
    with restarted() as db:
        runs = list(db.scalars(select(AnalyzerRun)))
        assert len(runs) == 2
        assert original_id in {run.id for run in runs}
        assert len(list(db.scalars(select(Finding)))) == 1
        assert db.get(Scan, scan).status == "completed"
