from typing import Annotated

from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, field_validator, Field, ValidationError
from database.validators.accounts import validate_email, validate_password_strength, validate_token

from database import accounts_validators


class UserBase(BaseModel):

    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        email = validate_email(value)

        return email


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        email = validate_email(value)

        return email

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        password = validate_password_strength(value)

        return password

class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class UserActivationRequestSchema(UserBase):
    token: str


