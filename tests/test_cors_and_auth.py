import pytest
from app.models import User, RoleEnum

def test_cors_headers_on_standard_request(client):
    origin = "https://zero-trust-document-vault.vercel.app"
    response = client.get('/auth/login', headers={'Origin': origin})
    assert response.headers.get('Access-Control-Allow-Origin') == origin
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'

def test_cors_preflight_options_request(client):
    origin = "https://zero-trust-document-vault.vercel.app"
    response = client.open(
        '/admin/verify-audit',
        method='OPTIONS',
        headers={
            'Origin': origin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type, Authorization'
        }
    )
    assert response.status_code == 200
    assert response.headers.get('Access-Control-Allow-Origin') == origin
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
    assert 'POST' in response.headers.get('Access-Control-Allow-Methods', '')

def test_cors_headers_on_unauthorized_error(client):
    # Unauthenticated request to protected endpoint should have CORS headers attached
    origin = "https://zero-trust-document-vault.vercel.app"
    response = client.post(
        '/admin/verify-audit',
        headers={'Origin': origin, 'Accept': 'application/json'}
    )
    assert response.status_code == 401
    assert response.headers.get('Access-Control-Allow-Origin') == origin
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
    data = response.get_json()
    assert data['error'] == 'Unauthorized'

def test_auth_me_unauthenticated(client):
    response = client.get('/auth/me', headers={'Accept': 'application/json'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['authenticated'] is False
    assert data['user'] is None

def test_auth_me_authenticated(admin_client):
    response = admin_client.get('/auth/me', headers={'Accept': 'application/json'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['authenticated'] is True
    assert data['user']['username'] == 'admin'
    assert data['user']['role'] == RoleEnum.ADMIN.value

def test_json_login_success_and_failure(client, admin_user):
    # Failure
    res_fail = client.post('/auth/login', json={'username': 'admin', 'password': 'WrongPassword!'})
    assert res_fail.status_code == 401
    assert res_fail.get_json()['success'] is False

    # Success
    res_ok = client.post('/auth/login', json={'username': 'admin', 'password': 'AdminSecret123!'})
    assert res_ok.status_code == 200
    assert res_ok.get_json()['success'] is True
    assert res_ok.get_json()['user']['username'] == 'admin'

def test_json_quick_login(client, owner_user):
    res = client.get('/auth/quick-login/alice', headers={'Accept': 'application/json'})
    assert res.status_code == 200
    assert res.get_json()['success'] is True
    assert res.get_json()['user']['username'] == 'alice'
