import pytest
from django.contrib.auth.models import User
from .token import generate_tokens_for_user, verify_token
from rest_framework_simplejwt.tokens import RefreshToken

@pytest.mark.django_db
def test_generate_tokens_for_user():
    """
    사용자에 대한 Access/Refresh 토큰 생성 테스트.
    """
    # 테스트 사용자 생성
    user = User.objects.create_user(username="testuser", password="testpassword")
    
    # 토큰 생성
    tokens = generate_tokens_for_user(user)
    
    assert "access" in tokens
    assert "refresh" in tokens

@pytest.mark.django_db
def test_verify_valid_token():
    """
    유효한 토큰 검증 테스트.
    """
    # 테스트 사용자 생성
    user = User.objects.create_user(username="testuser", password="testpassword")
    
    # 토큰 생성
    tokens = generate_tokens_for_user(user)
    
    # Access 토큰 검증
    result = verify_token(tokens["access"])
    
    assert result["is_valid"] is True
    assert result["user_id"] == user.id

@pytest.mark.django_db
def test_verify_invalid_token():
    """
    잘못된 토큰 검증 테스트.
    """
    invalid_token = "invalid.jwt.token"
    
    # 잘못된 토큰 검증
    result = verify_token(invalid_token)
    
    assert result["is_valid"] is False