from datetime import datetime, timezone, timedelta, date
import os
from os import access
from typing import cast
from dotenv import load_dotenv

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud import create_user, get_user_by_email, create_access_token, create_reset_token
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from database.validators.accounts import validate_token
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema
from schemas.accounts import UserBase, PasswordResetRequest
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager

load_dotenv()
router = APIRouter()
jwt_auth_manager = JWTAuthManager(os.getenv("SECRET_KEY_ACCESS"), os.getenv("SECRET_KEY_REFRESH"), os.getenv("JWT_SIGNING_ALGORITHM"))


# @router.post("/reset-password/complete/")
# async def password_reset_complete(data: PasswordResetRequest, db: Session = Depends(get_db)):


@router.post("/password-reset/request/", status_code=200)
async def password_reset_request(data: UserBase, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db=db, email=data.email)
    if user and user.is_active:
        await create_reset_token(db=db, user=user)
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/activate/", status_code=200)
async def user_activation(
    request: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(
            UserModel.email == request.email,
            ActivationTokenModel.token == request.token,
        )
    )
    token = (await db.execute(stmt)).scalars().first()

    if token is None:
        raise HTTPException(400, "Invalid or expired activation token.")

    expires_at = token.expires_at
    if expires_at.tzinfo is None:  # SQLite повертає naive datetime
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(400, "Invalid or expired activation token.")

    if token.user.is_active:
        raise HTTPException(400, "User account is already active.")

    token.user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/register/",
    status_code=201,
    response_model=UserRegistrationResponseSchema,
)
async def user_registration(
        schema_in: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        new_user = await create_user(db, schema_in)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, f"A user with this email {schema_in.email} already exists.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(500, "An error occurred during user creation.")
    return UserRegistrationResponseSchema.model_validate(new_user)
