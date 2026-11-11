import os
import random
import string
from datetime import timedelta, datetime, timezone
from typing import cast
from dotenv import load_dotenv
from sqlalchemy.orm import selectinload
from security.token_manager import JWTAuthManager
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import UserGroupEnum, UserGroupModel, ActivationTokenModel, PasswordResetTokenModel
from database.models.accounts import UserModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password


load_dotenv()
jwt_auth_manager = JWTAuthManager(
    secret_key_access=os.getenv("SECRET_KEY_ACCESS"),
    secret_key_refresh=os.getenv("SECRET_KEY_REFRESH"),
    algorithm=os.getenv("JWT_SIGNING_ALGORITHM")
)


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel:
    result = await db.execute(select(UserModel).options(
        selectinload(UserModel.password_reset_token)
    ).where(UserModel.email == email))

    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema) -> UserModel:

    hashed = hash_password(user.password)
    user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_gr = user_group.scalar_one_or_none()

    if user_gr is None:
        raise HTTPException(404 , "User group will not created")

    db_user = UserModel(email=user.email, _hashed_password=hashed, group_id=user_gr.id)

    db.add(db_user)
    await db.flush()

    activation_token = ActivationTokenModel(
        user_id=db_user.id,
        token=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
        expires_at=datetime.now(timezone.utc) + timedelta(days=15)
    )

    db.add(activation_token)
    await db.commit()
    await db.refresh(db_user, ["activation_token"])

    return db_user


async def create_reset_token(db: AsyncSession, user: UserModel):
    reset_token_model = PasswordResetTokenModel(
        user_id=cast(int, user.id),
        token=jwt_auth_manager._create_token(
            data={"sub": user.email},
            secret_key=os.getenv("SECRET_KEY_ACCESS"),
            expires_delta=timedelta(days=30)
        ),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30)
    )

    if user.password_reset_token:
        await db.delete(user.password_reset_token)
        await db.flush()

    user.password_reset_token = reset_token_model

    await db.commit()
    await db.refresh(user, ["password_reset_token"])
