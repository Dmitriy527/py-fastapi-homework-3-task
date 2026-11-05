import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
from jose import jwt

load_dotenv()

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import UserGroupEnum, UserGroupModel

from database.models.accounts import UserModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema) -> UserModel:

    hashed = hash_password(user.password)
    user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_gr = user_group.scalar_one_or_none()
    if user_gr is None:
        raise HTTPException(404 , "User group will not created")

    db_user = UserModel(email = user.email, _hashed_password=hashed, group_id=user_gr.id)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    return db_user

async def get_user_by_email(db: AsyncSession, email: str) -> UserModel:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        os.getenv("SECRET_KEY_ACCESS"),
        algorithm=os.getenv("JWT_SIGNING_ALGORITHM"),
    )
    return encoded_jwt