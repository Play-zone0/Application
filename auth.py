import jwt
import datetime
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Secret key for signing JWTs (Change this to a more secure one)
SECRET_KEY = "pavan"

# Define HTTPBearer security for authentication
security = HTTPBearer()

def create_jwt_token(user_id: str):
    """Generates a JWT token for a given user ID."""
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token valid for 1 hour
    payload = {"sub": user_id, "exp": expiration}  # 'sub' represents subject (user ID)
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_jwt_token(token: str):
    """Verifies a JWT token and extracts the payload."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Dependency that extracts the user info from JWT token in request header."""
    return verify_jwt_token(credentials.credentials)
