# FastAPI JWT Middleware

Simple JSON Web token authorisation for FastAPI framework, for those that appear to keep such functionality encapsulated in middleware.

## Usage

```python
from fastapi import FastAPI

# Define the path to the ceritifcate
CERT_PATH = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), 'certs/api_auth.cer')

# Initialise your FastAPI application, attaching the middleware
app = FastAPI()
app.add_middleware(JWTAuthorisation, config=JWTConfig(
    cert_path=CERT_PATH, algorithms=['RS256']))
```

The token data can be access from within routes by using the request's "state" property:

```python
@app.get('/hello_world')
def hello_world(request: Request):
    return {
        'content': 'Hello world',
        'jwt_data': request.state.jwt_data,
    }
```
