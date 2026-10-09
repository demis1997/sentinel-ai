import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.db import Base


def archive(entries: dict[str, str]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zipped:
        for name, content in entries.items():
            zipped.writestr(name, content)
    return stream.getvalue()


@pytest.fixture
def client(tmp_path):
    app = create_app(f"sqlite:///{tmp_path / 'test.db'}", tmp_path / "snapshots")
    Base.metadata.create_all(app.state.factory.kw["bind"])
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client
