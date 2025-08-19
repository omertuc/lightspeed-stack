"""Unit tests for the / endpoint handler."""

from fastapi import Request

from app.endpoints.root import root_endpoint_handler


def test_root_endpoint():
    """Test the root endpoint handler."""
    auth = ("test_user", "token", {})
    request = Request(
        scope={
            "type": "http",
        }
    )
    response = root_endpoint_handler(auth, request)
    assert response is not None
