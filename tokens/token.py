from rest_framework_simplejwt.tokens import RefreshToken

def generate_tokens_for_user(user):
    """
    사용자에 대해 Access/Refresh 토큰을 생성합니다.
    """
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }

def verify_token(token):
    """
    JWT 토큰의 유효성을 확인합니다.
    """
    try:
        refresh = RefreshToken(token)
        return {"is_valid": True, "user_id": refresh["user_id"]}
    except Exception as e:
        return {"is_valid": False, "error": str(e)}