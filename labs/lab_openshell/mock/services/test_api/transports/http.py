from typing import Any, Dict, List
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm

from ..auth.dependencies import (
    get_current_active_user_any,
    get_current_user_api_key,
    get_current_user_basic,
    get_current_user_jwt,
)
from ..core.emulator import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    fake_users_db,
    hotels,
)
from ..core.models import Hotel, Token, User

test_api_router = APIRouter(prefix="/test-api")


@test_api_router.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@test_api_router.get("/status", tags=["Health"])
async def get_status():
    return Response(status_code=200)


@test_api_router.get("/users/me/", response_model=User, tags=["Users"])
async def read_users_me(current_user: User = Depends(get_current_user_jwt)):
    return current_user


@test_api_router.get("/hotels/api-key/", response_model=List[Hotel], tags=["Hotels", "API Key"])
async def get_hotels_api_key(current_user: User = Depends(get_current_user_api_key)):
    return hotels


@test_api_router.get("/hotels/basic/", response_model=List[Hotel], tags=["Hotels", "Basic Auth"])
async def get_hotels_basic(current_user: User = Depends(get_current_user_basic)):
    return hotels


@test_api_router.get("/hotels/", response_model=List[Hotel], tags=["Hotels"])
async def get_hotels(current_user: User = Depends(get_current_active_user_any)):
    return hotels


@test_api_router.get("/hotels/{hotel_id}/", response_model=Hotel, tags=["Hotels"])
async def get_hotel(hotel_id: int, current_user: User = Depends(get_current_active_user_any)):
    hotel = next((h for h in hotels if h["id"] == hotel_id), None)
    if not hotel:
        raise HTTPException(status_code=404, detail="Hotel not found")
    return hotel


@test_api_router.post("/v1/chat/completions", tags=["AI Gateway"])
async def demo_chat_completions(payload: Dict[str, Any]):
    return {
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "gateway": payload.get("gateway", "demo"),
        "model": payload.get("model", "demo-model"),
        "choices": [{"message": {"role": "assistant", "content": "demo response"}}],
    }


@test_api_router.get("/v1/models", tags=["AI Gateway"])
async def demo_models():
    return {
        "object": "list",
        "gateway": "demo_gateway",
        "mode": "openai-compatible",
        "data": [{"id": "demo-model", "object": "model"}],
    }
