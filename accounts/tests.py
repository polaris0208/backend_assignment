from datetime import timedelta
from .models import User, Role
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken


class BaseTest(APITestCase):
    def setUp(self):
        self.signup_url = reverse("signup")
        self.login_url = reverse("login")
        self.protected_url = reverse("protected")

        self.user_role, _ = Role.objects.get_or_create(name="USER")

        self.user = User.objects.create_user(
            username="testuser", password="testpassword", nickname="Test Nickname"
        )
        self.user.roles.add(self.user_role)


class AuthenticationTests(BaseTest):
    def test_signup_success(self):
        payload = {
            "username": "newuser",
            "password": "newpassword",
            "nickname": "New Nickname",
        }
        response = self.client.post(self.signup_url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], payload["username"])
        self.assertEqual(response.data["nickname"], payload["nickname"])
        self.assertEqual(response.data["roles"], [{"role": "USER"}])

    def test_signup_failure(self):
        payload = {"username": "newuser"}
        response = self.client.post(self.signup_url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertIn("nickname", response.data)

    def test_login_success(self):
        payload = {"username": "testuser", "password": "testpassword"}
        response = self.client.post(self.login_url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)

    def test_login_failure(self):
        payload = {"username": "wronguser", "password": "wrongpassword"}
        response = self.client.post(self.login_url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signup_duplicate_username(self):
        payload = {
            "username": "testuser",
            "password": "newpassword",
            "nickname": "New Nickname",
        }
        response = self.client.post(self.signup_url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", response.data)

    def test_signup_duplicate_nickname(self):
        payload = {
            "username": "newuser",
            "password": "newpassword",
            "nickname": "Test Nickname",
        }
        response = self.client.post(self.signup_url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("nickname", response.data)


class JWTAuthenticationTests(BaseTest):

    def test_access_token_and_refresh_token_extraction(self):
        login_response = self.client.post(
            self.login_url, data={"username": "testuser", "password": "testpassword"}
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

        full_token = login_response.data.get("token")
        self.assertIsNotNone(full_token)

        refresh_token = RefreshToken(full_token)
        self.access_token = str(refresh_token.access_token)
        self.refresh_token = str(refresh_token)

        self.assertTrue(self.access_token)
        self.assertTrue(self.refresh_token)

    def test_access_token_validation_success(self):
        self.test_access_token_and_refresh_token_extraction()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_access_token_validation_failure(self):
        invalid_token = "invalid.jwt.token"
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {invalid_token}")
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_token_to_access_token_success(self):
        self.test_access_token_and_refresh_token_extraction()
        response = self.client.post(
            "/api/token/refresh/", data={"refresh": self.refresh_token}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_refresh_token_validation_failure(self):
        invalid_refresh_token = "invalid.refresh.token"
        response = self.client.post(
            "/api/token/refresh/", data={"refresh": invalid_refresh_token}
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_access_token_expiration(self):
        self.test_access_token_and_refresh_token_extraction()
        refresh_token = RefreshToken(self.refresh_token)
        expired_access_token = refresh_token.access_token
        expired_access_token.set_exp(lifetime=timedelta(seconds=-1))

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {expired_access_token}")
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_protected_endpoint_with_valid_token(self):
        self.test_access_token_and_refresh_token_extraction()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_protected_endpoint_without_token(self):
        response = self.client.get(self.protected_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
