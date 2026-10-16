from typing import Optional, Dict, List
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from .models import User, UserInDB


SECRET_KEY = "altprobe-demo-signing-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")


fake_users_db = {
    "demo_user": {
        "username": "demo_user",
        "full_name": "Demo User",
        "email": "demo.user@example.invalid",
        "hashed_password": "$5$rounds=535000$9XQdyDTVS/pzPpFj$q10zSYOZBcDiPPHmVUYzOKni46NRDCxalsaEPCixaE9",
        "disabled": False,
    }
}

hotels = [
    {"id": 1, "name": "Grand Hotel", "location": "Demo City"},
    {"id": 2, "name": "Harbor Resort", "location": "Sample Bay"},
]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user(db: Dict, username: str) -> Optional[UserInDB]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(fake_db: Dict, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
