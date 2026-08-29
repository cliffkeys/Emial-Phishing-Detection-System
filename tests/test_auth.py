import pytest
from app import create_app
from database.db import db
from database.models import User


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_user_password_hashing():
    user = User(username="testanalyst", email="test@mailshield.local")
    user.set_password("SuperSecretPass123!")
    assert user.password_hash != "SuperSecretPass123!"
    assert user.check_password("SuperSecretPass123!") is True
    assert user.check_password("WrongPassword") is False


def test_registration_success(client, app):
    res = client.post("/auth/register", data={
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }, follow_redirects=True)
    assert res.status_code == 200
    with app.app_context():
        u = User.query.filter_by(username="newuser").first()
        assert u is not None
        assert u.email == "newuser@example.com"


def test_duplicate_registration_prevented(client, app):
    with app.app_context():
        u = User(username="existing", email="existing@example.com")
        u.set_password("Pass1234")
        db.session.add(u)
        db.session.commit()

    res = client.post("/auth/register", data={
        "username": "existing",
        "email": "other@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }, follow_redirects=True)
    assert b"already taken" in res.data


def test_login_and_logout_flow(client, app):
    with app.app_context():
        u = User(username="loginuser", email="login@example.com")
        u.set_password("SecretPass99")
        db.session.add(u)
        db.session.commit()

    # Successful login
    res = client.post("/auth/login", data={
        "identifier": "loginuser",
        "password": "SecretPass99"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Threat Intelligence Dashboard" in res.data

    # Logout
    res_logout = client.get("/auth/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"logged out" in res_logout.data


def test_unauthenticated_protected_route_redirect(client):
    res = client.get("/dashboard", follow_redirects=False)
    assert res.status_code == 302
    assert "/auth/login" in res.location
