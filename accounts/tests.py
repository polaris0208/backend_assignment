from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth.models import User
from .models import Role

class UserAuthenticationTests(APITestCase):
    """회원가입 및 로그인 테스트"""

    def setUp(self):
        """테스트에 필요한 초기 데이터 설정"""
        self.signup_url = "/signup/"
        self.login_url = "/login/"
        self.protected_url = "/protected/"
        
        # 역할(Role) 생성
        self.user_role = Role.objects.create(name="USER")
        
        # 테스트 유저 생성
        self.user = User.objects.create_user(
            username="testuser",
            password="testpassword",
            nickname="Test Nickname"
        )
        self.user.roles.add(self.user_role)

    def test_signup_success(self):
        """회원가입 성공 테스트"""
        payload = {
            "username": "newuser",
            "password": "newpassword",
            "nickname": "New Nickname"
        }
        response = self.client.post(self.signup_url, data=payload)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], payload["username"])
        self.assertEqual(response.data["nickname"], payload["nickname"])
        self.assertEqual(response.data["roles"], [{"role": "USER"}])

    def test_signup_failure(self):
        """회원가입 실패 테스트 (필수 필드 누락)"""
        payload = {"username": "newuser"}  # 'password'와 'nickname' 누락
        response = self.client.post(self.signup_url, data=payload)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn("nickname", response.data)

    def test_login_success(self):
        """로그인 성공 테스트"""
        payload = {
            "username": "testuser",
            "password": "testpassword"
        }
        response = self.client.post(self.login_url, data=payload)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)

    def test_login_failure(self):
        """로그인 실패 테스트 (잘못된 자격 증명)"""
        payload = {
            "username": "wronguser",
            "password": "wrongpassword"
        }
        response = self.client.post(self.login_url, data=payload)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_protected_endpoint_with_valid_token(self):
        """유효한 토큰으로 보호된 엔드포인트 접근 테스트"""
        # 로그인 후 토큰 생성
        login_payload = {
            "username": "testuser",
            "password": "testpassword"
        }
        login_response = self.client.post(self.login_url, data=login_payload)
        
        token = login_response.data["token"]
        
        # Authorization 헤더에 토큰 추가
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        
        # 보호된 엔드포인트 요청
        response = self.client.get(self.protected_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_protected_endpoint_without_token(self):
        """토큰 없이 보호된 엔드포인트 접근 테스트"""
        response = self.client.get(self.protected_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_protected_endpoint_with_invalid_token(self):
        """잘못된 토큰으로 보호된 엔드포인트 접근 테스트"""
        invalid_token = "invalid.jwt.token"
        
        # Authorization 헤더에 잘못된 토큰 추가
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {invalid_token}")
        
        response = self.client.get(self.protected_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
