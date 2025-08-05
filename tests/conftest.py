from builtins import Exception, range, str
from datetime import timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from faker import Faker

from app.main import app
from app.database import Base, Database
from app.models.user_model import User, UserRole
from app.dependencies import get_db, get_settings
from app.utils.security import hash_password
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import create_access_token

fake = Faker()

settings = get_settings()
TEST_DATABASE_URL = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
engine = create_async_engine(TEST_DATABASE_URL, echo=settings.debug)
AsyncTestingSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

def truncate(s: str, max_len: int) -> str:
    return s[:max_len]

@pytest.fixture
def app():
    from app.main import app as fastapi_app
    return fastapi_app

@pytest.fixture
def email_service():
    template_manager = TemplateManager()
    email_service = EmailService(template_manager=template_manager)
    return email_service

@pytest.fixture(scope="function")
async def async_client(app, db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        try:
            yield client
        finally:
            app.dependency_overrides.clear()

@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    try:
        Database.initialize(settings.database_url)
    except Exception as e:
        pytest.fail(f"Failed to initialize the database: {str(e)}")

@pytest.fixture(scope="function", autouse=True)
async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()

@pytest.fixture(scope="function")
async def db_session(setup_database):
    async with AsyncTestingSessionLocal() as session:
            yield session

@pytest.fixture(scope="function")
async def locked_user(db_session):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"{fake.unique.user_name()}_{uuid4()}", max_nickname_len)
    email = truncate(f"{fake.unique.email()}_{uuid4()}", max_email_len)
    first_name = truncate(fake.first_name(), max_name_len)
    last_name = truncate(fake.last_name(), max_name_len)

    user_data = {
        "nickname": nickname,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": True,
        "failed_login_attempts": settings.max_login_attempts,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
async def user(db_session):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"{fake.unique.user_name()}_{uuid4()}", max_nickname_len)
    email = truncate(f"{fake.unique.email()}_{uuid4()}", max_email_len)
    first_name = truncate(fake.first_name(), max_name_len)
    last_name = truncate(fake.last_name(), max_name_len)

    user_data = {
        "nickname": nickname,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
async def verified_user(db_session):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"{fake.unique.user_name()}_{uuid4()}", max_nickname_len)
    local, domain = fake.unique.email().split('@')
    email_with_uuid = f"{local}_{uuid4()}@{domain}"
    email = truncate(email_with_uuid, max_email_len)
    first_name = truncate(fake.first_name(), max_name_len)
    last_name = truncate(fake.last_name(), max_name_len)

    user_data = {
        "nickname": nickname,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": True,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
async def unverified_user(db_session):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"{fake.unique.user_name()}_{uuid4()}", max_nickname_len)
    email = truncate(f"{fake.unique.email()}_{uuid4()}", max_email_len)
    first_name = truncate(fake.first_name(), max_name_len)
    last_name = truncate(fake.last_name(), max_name_len)

    user_data = {
        "nickname": nickname,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
async def users_with_same_role_50_users(db_session):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    users = []
    for i in range(50):
        nickname = truncate(f"{fake.unique.user_name()}_{i}_{uuid4()}", max_nickname_len)
        email = truncate(f"user{i}_{uuid4()}@email.com", max_email_len)
        first_name = truncate(fake.first_name(), max_name_len)
        last_name = truncate(fake.last_name(), max_name_len)

        user_data = {
            "nickname": nickname,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "hashed_password": hash_password("MySuperPassword$1234"),
            "role": UserRole.AUTHENTICATED,
            "email_verified": False,
            "is_locked": False,
        }
        user = User(**user_data)
        db_session.add(user)
        users.append(user)
    await db_session.commit()
    for user in users:
        await db_session.refresh(user)
    return users

@pytest.fixture
async def admin_user(db_session: AsyncSession):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"admin_{uuid4()}", max_nickname_len)
    email = truncate(f"admin_{uuid4()}@example.com", max_email_len)

    user = User(
        nickname=nickname,
        email=email,
        first_name="John",
        last_name="Doe",
        hashed_password=hash_password("securepassword"),
        role=UserRole.ADMIN,
        is_locked=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture
async def manager_user(db_session: AsyncSession):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"manager_{uuid4()}", max_nickname_len)
    email = truncate(f"manager_{uuid4()}@example.com", max_email_len)

    user = User(
        nickname=nickname,
        email=email,
        first_name="John",
        last_name="Doe",
        hashed_password=hash_password("securepassword"),
        role=UserRole.MANAGER,
        is_locked=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture(scope="function")
def admin_token(admin_user):
    token_data = {"sub": str(admin_user.id), "role": admin_user.role.name}
    return create_access_token(data=token_data, expires_delta=timedelta(minutes=30))

@pytest.fixture(scope="function")
def manager_token(manager_user):
    token_data = {"sub": str(manager_user.id), "role": manager_user.role.name}
    return create_access_token(data=token_data, expires_delta=timedelta(minutes=30))

@pytest.fixture(scope="function")
def user_token(user):
    token_data = {"sub": str(user.id), "role": user.role.name}
    return create_access_token(data=token_data, expires_delta=timedelta(minutes=30))

@pytest.fixture
def mock_email_service():
    if settings.send_real_mail == 'true':
        return EmailService()
    else:
        mock_service = AsyncMock(spec=EmailService)
        mock_service.send_verification_email.return_value = None
        mock_service.send_user_email.return_value = None
        return mock_service
    
# adding other_user fixture
@pytest.fixture(scope="function")
async def other_user(db_session):
    max_nickname_len = 50
    max_email_len = 255
    max_name_len = 100

    nickname = truncate(f"{fake.unique.user_name()}_{uuid4()}", max_nickname_len)
    email = truncate(f"{fake.unique.email()}_{uuid4()}", max_email_len)
    first_name = truncate(fake.first_name(), max_name_len)
    last_name = truncate(fake.last_name(), max_name_len)

    user_data = {
        "nickname": nickname,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": True,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

