import os

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi_jwt_middleware.jwt_auth import JWTAuthorisation, JWTConfig
from jose import jwt

PRIV_PATH = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), '_certs/test.key')
CERT_PATH = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), '_certs/test.cer')

app = FastAPI()

app.add_middleware(JWTAuthorisation, config=JWTConfig(
    cert_path=CERT_PATH, algorithms=['RS256']))


@app.get('/test')
def sut(request: Request):
    return {'content': 'Hello world', 'jwt_data': request.state.jwt_data}


client = TestClient(app)


def _make_token(data: dict):
    with open(PRIV_PATH, 'r') as f:
        privkey = f.read()
        return jwt.encode(data, privkey, algorithm='RS256')


def test_authorised_call():
    token = _make_token({'foo': 'bar'})
    response = client.get(
        '/test', headers={'Authorization': f'Bearer {token}'})

    assert response.status_code == 200


def test_no_credentials():
    response = client.get('/test')

    assert response.status_code == 403
    assert response.json()['detail'] == 'Not authenticated'


def test_incorrect_scheme():
    response = client.get('/test', headers={'Authorization': 'Basic foobar'})

    assert response.status_code == 403
    assert response.json()['detail'] == 'Invalid authentication credentials'
