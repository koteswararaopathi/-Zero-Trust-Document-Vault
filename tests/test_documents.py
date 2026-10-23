import io
from app.models import Document, User

def test_unauthenticated_request_handling(client, sample_document):
    """
    Unauthenticated users attempting to access protected endpoints
    are redirected to login or returned 401.
    """
    res = client.get(f'/download/{sample_document.id}')
    assert res.status_code == 302
    assert '/auth/login' in res.headers.get('Location', '')

    # Unauthenticated API request
    api_res = client.get(f'/download/{sample_document.id}', headers={'Accept': 'application/json'})
    assert api_res.status_code == 401

def test_download_nonexistent_document_returns_404(owner_client):
    """
    Attempting to download a document ID that does not exist returns 404.
    """
    res = owner_client.get('/download/999999')
    assert res.status_code == 404

def test_upload_missing_file_redirects(owner_client):
    """
    Submitting an upload form with empty data fails gracefully.
    """
    res = owner_client.post('/upload', data={}, follow_redirects=True)
    assert res.status_code == 200
    assert b"No file part provided" in res.data

def test_password_hashing_security(app):
    """
    Verifies secure password hashing with salt using Werkzeug generate_password_hash.
    """
    user = User(username='testsec', email='testsec@local.vault', role='Viewer')
    user.set_password('PlainTextPassword123')
    assert user.password_hash != 'PlainTextPassword123'
    assert user.check_password('PlainTextPassword123') is True
    assert user.check_password('WrongPassword') is False
