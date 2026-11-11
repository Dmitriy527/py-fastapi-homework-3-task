import os
from datetime import timedelta, datetime, timezone
from typing import cast

from dotenv import load_dotenv
from jose import jwt
from sqlalchemy.orm import selectinload

from security.token_manager import JWTAuthManager

load_dotenv()

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import UserGroupEnum, UserGroupModel, ActivationTokenModel, PasswordResetTokenModel

from database.models.accounts import UserModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password


jwt_auth_manager = JWTAuthManager(os.getenv("SECRET_KEY_ACCESS"), os.getenv("SECRET_KEY_REFRESH"), os.getenv("JWT_SIGNING_ALGORITHM"))


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel:
    result = await db.execute(select(UserModel).options(selectinload(UserModel.password_reset_token)).where(UserModel.email == email))
    return result.scalar_one_or_none()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
        to_encode.update(to_encode, expires_delta=expire)
    else:
        to_encode.update(to_encode)


    encoded_jwt = jwt.encode(
        to_encode,
        os.getenv("SECRET_KEY_ACCESS"),
        algorithm=os.getenv("JWT_SIGNING_ALGORITHM"),
    )
    return encoded_jwt

async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema) -> UserModel:

    hashed = hash_password(user.password)
    user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_gr = user_group.scalar_one_or_none()
    if user_gr is None:
        raise HTTPException(404 , "User group will not created")

    db_user = UserModel(email = user.email, _hashed_password=hashed, group_id=user_gr.id)
    db.add(db_user)
    await db.flush()
    activation_token = ActivationTokenModel(
        user_id=db_user.id,
        token=jwt_auth_manager.create_access_token(data={"sub": user.email}),
        expires_at=datetime.now(timezone.utc) + timedelta(days=15)
    )
    db.add(activation_token)
    await db.commit()
    await db.refresh(db_user, ["activation_token"])

    return db_user

async def create_reset_token(db: AsyncSession, user: UserModel):
    reset_token_model = PasswordResetTokenModel(user_id=cast(int, user.id))
    if user.password_reset_token:
        await db.delete(user.password_reset_token)
        await db.flush()
    user.password_reset_token = reset_token_model
    await db.commit()
    await db.refresh(user,["password_reset_token"])
