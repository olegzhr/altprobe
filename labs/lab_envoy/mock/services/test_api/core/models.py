from typing import List, Optional
from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


class Hotel(BaseModel):
    id: int
    name: str
    location: str


class TestStatusRequest(BaseModel):
    text_type: str = Field(..., description="Type of text, e.g. 'HTTP'")
    text_sample: str = Field(..., description="Sample text")
    artifact_type: str = Field(..., description="Artifact type, e.g. 'Pytest'")
