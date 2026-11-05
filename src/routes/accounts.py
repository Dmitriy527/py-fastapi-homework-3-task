from datetime import datetime, timezone, timedelta
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
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

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
        new_user.access_token = create_access_token(data={"sub": schema_in.email}, expires_delta=access_token_expires)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, f"A user with this email {schema_in.email} already exists.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(500, "An error occurred during user creation.")

    work_user_for_add_access_token = await db.scalar(select(UserModel).where(UserModel.id == new_user.id))
    access_token_expires = timedelta(days=15)
    work_user_for_add_access_token.access_token = create_access_token(data={"sub": schema_in.email}, expires_delta=access_token_expires)
    await db.commit()
    await db.refresh(work_user_for_add_access_token)
    return UserRegistrationResponseSchema.model_validate(work_user_for_add_access_token)