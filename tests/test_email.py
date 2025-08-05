from unittest.mock import MagicMock, patch
import pytest
from app.services.email_service import EmailService
import os

@pytest.mark.skipif(os.getenv("CI") == "true", reason="Skip real email tests in CI")
@pytest.mark.asyncio
@patch("app.utils.smtp_connection.SMTPClient")
async def test_send_markdown_email(mock_smtp_client_class):

    mock_smtp_client = MagicMock()
    mock_smtp_client.send_email.return_value = None
    mock_smtp_client_class.return_value = mock_smtp_client

    mock_template_manager = MagicMock()
    email_service = EmailService(template_manager=mock_template_manager)

    email_service.smtp_client = mock_smtp_client

    user_data = {
        "email": "test@example.com",
        "name": "Test User",
        "verification_url": "http://example.com/verify?token=abc123"
    }

    await email_service.send_user_email(user_data, 'email_verification')

    mock_smtp_client.send_email.assert_called_once()
