from builtins import range
import pytest
import os
from sqlalchemy import select
from app.dependencies import get_settings
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.exc import IntegrityError
from app.models.user_model import User, UserRole
from app.services.user_service import UserService, EmailService
from app.utils.nickname_gen import generate_nickname
from uuid import uuid4

pytestmark = pytest.mark.asyncio

# Adding helper
def unique_str(base: str, max_len: int) -> str:
    suffix = f"_{uuid4()}"
    allowed_len = max_len - len(suffix)
    return base[:allowed_len] + suffix

# Fixture modification just in case
@pytest.fixture(scope="function")
async def user(db_session):
    nickname = unique_str(generate_nickname(), 50)
    email = unique_str("user@example.com", 255)
    user_data = {
        "nickname": nickname,
        "email": email,
        "hashed_password": "hashedpasswordplaceholder",
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

# Test creating a user with valid data
@pytest.mark.skipif(os.getenv("CI") == "true", reason="Skip real email tests in CI")
@patch("app.utils.smtp_connection.SMTPClient")
@pytest.mark.asyncio
async def test_create_user_with_valid_data(mock_smtp_client_class, db_session):
    mock_smtp_client = MagicMock()
    mock_smtp_client.send_email.return_value = None
    mock_smtp_client_class.return_value = mock_smtp_client

    mock_template_manager = MagicMock()
    email_service = EmailService(template_manager=mock_template_manager)
    email_service.smtp_client = mock_smtp_client 

    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name,
    }

    user = await UserService.create(db_session, user_data, email_service)
    assert user.email == user_data["email"]

    mock_smtp_client.send_email.assert_called_once()

# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None

# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "non_existent_email@example.com")
    assert retrieved_user is None

# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    new_email = "updated_email@example.com"
    updated_user = await UserService.update(db_session, user.id, {"email": new_email})
    assert updated_user is not None
    assert updated_user.email == new_email

# Test updating a user with invalid data
async def test_update_user_invalid_data(db_session, user):
    updated_user = await UserService.update(db_session, user.id, {"email": "invalidemail"})
    assert updated_user is None

# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    deletion_success = await UserService.delete(db_session, user.id)
    assert deletion_success is True

# Test attempting to delete a user who does not exist
async def test_delete_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    deletion_success = await UserService.delete(db_session, non_existent_user_id)
    assert deletion_success is False

# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10
    assert len(users_page_2) == 10
    assert users_page_1[0].id != users_page_2[0].id

# Test registering a user with valid data
@pytest.mark.skipif(os.getenv("CI") == "true", reason="Skip real email tests in CI")
@patch("app.utils.smtp_connection.SMTPClient")
@pytest.mark.asyncio
async def test_register_user_with_valid_data(mock_smtp_client_class, db_session):
    mock_smtp_client = MagicMock()
    mock_smtp_client.send_email.return_value = None

    mock_template_manager = MagicMock()
    email_service = EmailService(
        template_manager=mock_template_manager,
        smtp_client=mock_smtp_client)

    user_data = {
        "nickname": generate_nickname(),
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
        "role": UserRole.ADMIN
    }

    user = await UserService.register_user(db_session, user_data, email_service)
    assert user.email == user_data["email"]

# Test attempting to register a user with invalid data
async def test_register_user_with_invalid_data(db_session, email_service):
    user_data = {
        "email": "registerinvalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is None

# Test successful user login
async def test_login_user_successful(db_session, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "MySuperPassword$1234",
    }
    logged_in_user = await UserService.login_user(db_session, user_data["email"], user_data["password"])
    assert logged_in_user is not None

# Test user login with incorrect email
async def test_login_user_incorrect_email(db_session):
    user = await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")
    assert user is None

# Test user login with incorrect password
async def test_login_user_incorrect_password(db_session, user):
    user = await UserService.login_user(db_session, user.email, "IncorrectPassword!")
    assert user is None

# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_login_attempts = get_settings().max_login_attempts
    for _ in range(max_login_attempts):
        await UserService.login_user(db_session, verified_user.email, "wrongpassword")
    
    is_locked = await UserService.is_account_locked(db_session, verified_user.email)
    assert is_locked, "The account should be locked after the maximum number of failed login attempts."

# Test resetting a user's password
async def test_reset_password(db_session, user):
    new_password = "NewPassword123!"
    reset_success = await UserService.reset_password(db_session, user.id, new_password)
    assert reset_success is True

# Test verifying a user's email
async def test_verify_email_with_token(db_session, user):
    token = "valid_token_example"  # This should be set in your user setup if it depends on a real token
    user.verification_token = token  # Simulating setting the token in the database
    await db_session.commit()
    result = await UserService.verify_email_with_token(db_session, user.id, token)
    assert result is True

# Test unlocking logic directly (used by the admin/manger endpoint)
async def test_unlock_user_account(db_session, locked_user):
    unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
    assert unlocked, "The account should be unlocked"
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked, "The user should no longer be locked"

'''TEST 3 START'''

# tests behavior of retry logic successfully passing
@pytest.mark.asyncio
async def test_create_user_succeeds_after_retries(db_session, mock_email_service):
    user_data = {
        "nickname": generate_nickname(), 
        "email": "test@example.com",
        "password": "securePass123",
        "role": "ANONYMOUS"
    }

    UserService.get_by_email = AsyncMock(return_value=None)
    UserService.count = AsyncMock(return_value=1)

    add_attempts = 0

    async def commit_side_effect():
        nonlocal add_attempts
        add_attempts += 1
        if add_attempts < 3:
            raise IntegrityError("duplicate", {}, None)
        else:
            return None

    db_session.add = AsyncMock()

    with patch.object(db_session, "commit", new=AsyncMock(side_effect=commit_side_effect)):
        with patch.object(db_session, "rollback", new=AsyncMock()):
            user = await UserService.create(db_session, user_data, mock_email_service)

    assert user is not None
    assert add_attempts == 3
    mock_email_service.send_verification_email.assert_awaited_once_with(user)


# tests behavior of retry logic unsuccessfully passing
@pytest.mark.asyncio
async def test_create_user_fails_after_max_retries(db_session, mock_email_service):
    user_data = {
        "nickname": generate_nickname(), 
        "email": "test@example.com",
        "password": "securePass123",
        "role": "ANONYMOUS"
    }

    UserService.get_by_email = AsyncMock(return_value=None)
    UserService.count = AsyncMock(return_value=1)
    mock_email_service.send_verification_email = AsyncMock()

    db_session.add = AsyncMock()

    with patch.object(db_session, "commit", new=AsyncMock(side_effect=IntegrityError("duplicate", {}, None))):
        with patch.object(db_session, "rollback", new=AsyncMock()):
            user = await UserService.create(db_session, user_data, mock_email_service)

    assert user is None
    mock_email_service.send_verification_email.assert_not_awaited()

'''TEST 3 END'''

'''TEST 6 START'''

# tests that status update is denied by nonadmins/nonmangers
@pytest.mark.asyncio
async def test_status_update_denied_for_users(db_session, user, other_user):
    user.role = UserRole.ANONYMOUS
    await db_session.commit()

    result = await UserService.update_status_to_professional(
        db_session=db_session,
        acting_user=user,
        target_user_id=other_user.id
    )
    assert result is None

'''TEST 6 END'''

'''TEST 7 START'''

# test that status updates for admin and manager
@pytest.mark.asyncio
async def test_status_update_success_for_admin_and_manager(db_session, admin_user, manager_user, user):
    for acting_user in (admin_user, manager_user):
        user.role = UserRole.AUTHENTICATED
        await db_session.commit()

        result = await UserService.update_status_to_professional(
            db_session=db_session,
            acting_user=acting_user,
            target_user_id=user.id
        )

        await db_session.refresh(user)
        assert result is not None
        assert isinstance(result, User)
        assert user.role == UserRole.PROFESSIONAL

'''TEST 7 END'''

'''TEST 8 START'''

# test the notification gets sent when status is updated
@pytest.mark.asyncio
async def test_notification_updated_status_sent():
    mock_email_service = AsyncMock()
    test_user = User(email="test@example.com", role="PROFESSIONAL")

    await UserService.notify_user_of_update(mock_email_service, test_user)

    mock_email_service.send_user_email.assert_awaited_once_with(
        recipient="test@example.com",
        subject="Status is updated!",
        template_name="user_promoted.html",
        context={"user": test_user},
    )

'''TEST 8 END'''

'''TEST 9 START'''

# tests that invalid inputs are rejected when updating profile
@pytest.mark.asyncio
async def test_update_user_profile_invalid_fields(db_session, user):
    update_data = {
        "first_name": "a" * 50,
        "github_profile_url": "not_a_url",
        "password": "short", 
    }

    updated_user = await UserService.update(db_session, user.id, update_data)
    assert updated_user is None

'''TEST 9 END'''

'''TEST 10 START'''

# tests that status is not upgraded again if already professional
@pytest.mark.asyncio
async def test_status_upgrade_skipped_if_professional_already(db_session, admin_user, user):
    user.role = UserRole.PROFESSIONAL
    await db_session.commit()

    result = await UserService.update_status_to_professional(
        db_session=db_session,
        acting_user=admin_user,
        target_user_id=user.id
    )

    assert result is None

'''TEST 10 END'''