from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate, UserUpdateAdmin, UserUpdatePublic
from app.services.email_service import EmailService
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()
            existing_user = await cls.get_by_email(session, validated_data['email'])
            if existing_user:
                logger.error("User with given email already exists.")
                return None

            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            validated_data.pop('nickname', None)
            validated_data.pop('role', None)

            user_count = await cls.count(session)
            role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS
            email_verified = role == UserRole.ADMIN
            verification_token = generate_verification_token()

            max_attempts = 5
            for attempt in range(max_attempts):
                new_nickname = generate_nickname()
                user_instance = User(
                    **validated_data,
                    nickname=new_nickname,
                    role=role,
                    email_verified=email_verified,
                    verification_token=verification_token
                )

                try:
                    session.add(user_instance)
                    await session.commit()
                    await email_service.send_verification_email(user_instance)
                    return user_instance
                except IntegrityError:
                    await session.rollback()
                    logger.warning(f"Nickname collision on attempt {attempt + 1}: {new_nickname}")

            logger.error("Failed to generate unique nickname after multiple attempts.")
            return None

        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None


    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            # remove sensitive fields if its present to prevent updates from unauthorized users
            sensitive_fields = {"role", "email_verified", "is_locked", "verification_token", "failed_login_attempts"}
            for field in sensitive_fields:
                if field in update_data:
                    update_data.pop(field)

            # validated_data = UserUpdate(**update_data).dict(exclude_unset=True)
            validated_data = UserUpdatePublic(**update_data).model_dump(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)  # Explicitly refresh the updated user object
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:  # Broad exception handling for debugging
            logger.error(f"Error during user update: {e}")
            return None
        
# adding the admin/managers updates here
    @classmethod
    async def admin_update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            validated_data = UserUpdateAdmin(**update_data).model_dump(exclude_unset=True)

            # adding notification feature to be sent when status is updated
            user_before = await cls.get_by_id(session, user_id)
            if not user_before:
                return None

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            query = (update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch"))
            await cls._execute_query(session, query)

            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)
                logger.info(f"[ADMIN] User {user_id} updated successfully.")

                # send notification if professional status does get upgraded
                was_professional = user_before.is_professional
                now_professinal = updated_user.is_professional
                if not was_professional and now_professinal:
                    await email_service.send_professional_status_upgraded_email(updated_user)
                return updated_user
            else:
                logger.error(f"[ADMIN] User {user_id} not found after update attempt.")
                return None

        except Exception as e:
            logger.error(f"[ADMIN] Error during user update: {e}")
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

# properly injecting EmailService isntance.
    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        return await cls.create(session, user_data, email_service)
    

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        user = await cls.get_by_email(session, email)
        if user:
            if user.email_verified is False:
                logger.warning(f"Login failed for {email}: email not verified.")
                return None
            if user.is_locked:
                logger.warning(f"Login failed for {email}: account is now locked due to failed attempts.")
                return None
            if verify_password(password, user.hashed_password):
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                logger.info(f"User {email} logged in sucessfully.")
                return user
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                    logger.warning(f'User {email} is locked due to failed login attempts.')
                else:
                    logger.warning(f"Incorrect password attemp for {email}.")
                session.add(user)
                await session.commit()
        else:
            logger.warning(f"Login attempt failed. {email} not found.")
        return None

# added class to allow admin-only to unlock and reset attempts
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return user.is_locked if user else False


    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            if user.role == UserRole.ANONYMOUS:
                user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
    
# staticmethod for updating status
    @staticmethod
    async def update_status_to_professional(db_session: AsyncSession, acting_user: User, target_user_id: int) -> User | None:
        if acting_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
            return None

        target_user = await db_session.get(User, target_user_id)
        if not target_user:
            return None


        if target_user.role == UserRole.PROFESSIONAL:
            return None
    
        target_user.role = UserRole.PROFESSIONAL
        await db_session.commit()
        return target_user

# notification sent when status is updated
    @staticmethod
    async def notify_user_of_update(email_service: EmailService, user: User):
        await email_service.send_user_email(
            recipient=user.email,
            subject="Status is updated!",
            template_name="user_promoted.html",
            context={"user": user}
        )

