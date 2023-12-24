from unittest.mock import patch

from sqlalchemy import create_engine
import requests

mock_engine = create_engine("sqlite://", echo=True)


# TODO: fix tests
@patch("src.db.engine.engine", mock_engine)
def test_create_user():
    resp = requests.post("http://server:8000/user/create_user", json={"name": "test", "password": "test"})
    assert resp.status_code == 200
