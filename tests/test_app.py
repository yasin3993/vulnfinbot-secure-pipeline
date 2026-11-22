import pytest

from app import create_app
from app.routes import MAX_MESSAGE_LENGTH


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as c:
        yield c


def test_health_check(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "healthy"}


def test_chat_success(client):
    r = client.post("/api/chat", json={"message": "How can I manage my monthly budget?"})
    assert r.status_code == 200
    assert r.get_json() == {"response": "You can start by tracking your income and expenses."}


def test_empty_message_rejected(client):
    r = client.post("/api/chat", json={"message": "   "})
    assert r.status_code == 400
    assert "empty" in r.get_json()["error"]


def test_missing_message_rejected(client):
    r = client.post("/api/chat", json={"text": "hello"})
    assert r.status_code == 400
    assert "required" in r.get_json()["error"]


def test_invalid_json(client):
    r = client.post("/api/chat", data="{not json", content_type="application/json")
    assert r.status_code == 400
    assert r.get_json() == {"error": "Invalid JSON body"}


def test_wrong_content_type(client):
    r = client.post("/api/chat", data="message=hi", content_type="text/plain")
    assert r.status_code == 415


def test_too_long_message_rejected(client):
    r = client.post("/api/chat", json={"message": "a" * (MAX_MESSAGE_LENGTH + 1)})
    assert r.status_code == 413


@pytest.mark.parametrize("value", [123, None, ["list"], {"a": 1}, True])
def test_unexpected_type(client, value):
    r = client.post("/api/chat", json={"message": value})
    assert r.status_code == 400
    assert "string" in r.get_json()["error"]


def test_json_array_body(client):
    r = client.post("/api/chat", json=["message"])
    assert r.status_code == 400


def test_unknown_route_no_stacktrace(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404
    assert b"Traceback" not in r.data


def test_security_headers(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
