from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from jose import JWTError, jwt

from ..core.models import User
from ..core.emulator import SECRET_KEY, ALGORITHM, fake_users_db, authenticate_user, get_user
from .config import COOKIE_NAME, API_KEY_NAME, API_KEY

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
security_basic = HTTPBasic(auto_error=False)


async def get_current_user_jwt(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate JWT credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if token is None:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_user_cookie(request: Request):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate cookie credentials",
    )
    token = request.cookies.get(COOKIE_NAME)
    if token is None:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_user_api_key(api_key: str = Depends(api_key_header)):
    if api_key is None or api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API Key",
        )
    return User(
        username="api_user",
        full_name="API Client",
        email="api@example.invalid",
        disabled=False,
    )


async def get_current_user_basic(credentials: HTTPBasicCredentials = Depends(security_basic)):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Basic credentials required",
            headers={"WWW-Authenticate": "Basic"},
        )
    user = authenticate_user(fake_users_db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


async def get_current_user_any(
    jwt_user: Optional[User] = Depends(get_current_user_jwt),
    cookie_user: Optional[User] = Depends(get_current_user_cookie),
    api_user: Optional[User] = Depends(get_current_user_api_key),
    basic_user: Optional[User] = Depends(get_current_user_basic),
):
    user = jwt_user or cookie_user or api_user or basic_user
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (try JWT Bearer, JWT Cookie, API Key, or Basic)",
        )
    return user


async def get_current_active_user_any(current_user: User = Depends(get_current_user_any)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
