from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token, decode_token
from app.models.user import User
from app.schemas.scan import UserRegister, UserLogin, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Returns current user if token is valid, None otherwise (allows anonymous scans)."""
    if not credentials:
        return None
    user_id = decode_token(credentials.credentials)
    if not user_id:
        return None
    return await db.get(User, user_id)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Returns current user or raises 401."""
    user = await get_current_user_optional(credentials, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return user


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(payload: UserRegister, db: AsyncSession = Depends(get_db)):
    # Check if email already exists
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered.")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(user.id)
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token(user.id)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
