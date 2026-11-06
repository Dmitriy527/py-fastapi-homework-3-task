from datetime import datetime, timezone, timedelta, date
from os import access
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud import create_user, get_user_by_email, create_access_token
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
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

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
        new_user.access_token = create_access_token(data={"sub": schema_in.email})
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, f"A user with this email {schema_in.email} already exists.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(500, "An error occurred during user creation.")
    return UserRegistrationResponseSchema.model_validate(new_user)
