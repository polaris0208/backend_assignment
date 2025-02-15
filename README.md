# 백엔드 개발 온보딩 과제 (Python)

## Requirements

- [x] Pytest를 이용한 테스트 코드 작성법 이해

- [x] Django를 이용한 인증과 권한 이해

- [x] JWT와 구체적인 알고리즘의 이해

- [x] PR 날려보기

- [x] 리뷰 바탕으로 개선하기

- [x] EC2에 배포해보기


### 시나리오 설계 및 코딩 시작!

**Django 기본 이해**
- [x] Middleware란 무엇인가? (with Decorators)
  <details>
    <summary>상세보기</summary>

  ## Django 미들웨어
  - **Django** 애플리케이션의 입력 또는 출력을 전역적으로 변경하기 위한 프레임워크

  ### `settings.py`
  - 순서가 중요
    - 요청과 응답은 미들웨어를 순차적으로 통과
    - 미들웨어에 의존성을 고려하여 순서 설정

  ```py
  MIDDLEWARE = [
      'django.middleware.security.SecurityMiddleware',
      'django.contrib.sessions.middleware.SessionMiddleware',
      'django.middleware.common.CommonMiddleware',
      'django.middleware.csrf.CsrfViewMiddleware',
      'django.contrib.auth.middleware.AuthenticationMiddleware',
      'django.contrib.messages.middleware.MessageMiddleware',
      'django.middleware.clickjacking.XFrameOptionsMiddleware',
      ...
  ]
  ```

  ### 작동방식
  - 나열된 순서대로 **HttpRequest** 처리.
    - 각 미들웨어의 `process_request(), process_view()` 메서드 실행
  - `View`에서 로직 실행
  - 응답은 역순으로 미들웨어 통과하며 `process_response()` 메서드 실행

  ## 커스텀 미들웨어 작성
  - 클래스형, 함수형으로 작성

  ### 함수 기반 미들웨어
  - 간단한 로직 구현에 적합

  ```py
  # custom_middleware.py
  from time import process_time_ns

  def view_process_time_middleware(get_response):
      def middleware(request):
          start_time = process_time_ns()
          response = get_response(request)
          end_time = process_time_ns()

          # 처리 시간을 응답 헤더에 추가
          if not response.has_header("View-Process-Run-Time"):
              response["View-Process-Run-Time"] = end_time - start_time
          return response

      return middleware
  ```

  #### 등록

  ```yml
  MIDDLEWARE = [
      ...
      'path.to.custom_middleware.view_process_time_middleware',
  ]
  ```

  ### 클래스 기반 미들웨어
  - 확장성이 높아 복잡한 로직 구현에 적합
  - 구조화된 형태로 추가 메서드 정의 가능

  ```py
  # custom_middleware.py
  from time import process_time_ns

  class ViewProcessTimeMiddleware:
      def __init__(self, get_response):
          self.get_response = get_response

      def __call__(self, request):
          start_time = process_time_ns()
          response = self.get_response(request)
          end_time = process_time_ns()

          if not response.has_header("View-Process-Run-Time"):
              response["View-Process-Run-Time"] = end_time - start_time

          return response
  ```

  ### 미들웨어 훅

  #### 정의 가능 메서드
  - `process_view(request, view_func, view_args, view_kwargs):`
    - 뷰 호출 직전에 실행
    - 요청 수정 또는 `HttpResponse` 반환으로 뷰 우회 가능
  - `process_exception(request, exception):`
    - 뷰에서 예외 발생 시 호출.
    - 예외 처리 또는 `HttpResponse` 반환 가능
  - `process_template_response(request, response):`
    - 응답이 `TemplateResponse`일 경우 호출
    - 템플릿 또는 컨텍스트 수정 가능

  ```py
  class CustomHookMiddleware:
      def __init__(self, get_response):
          self.get_response = get_response

      def process_view(self, request, view_func, view_args, view_kwargs):
          print("뷰 실행 전")
          return None  # 다음 미들웨어 또는 뷰로 계속 진행

      def process_exception(self, request, exception):
          print("예외 발생:", exception)
          return None  # 기본 예외 처리를 계속 진행

      def process_template_response(self, request, response):
          if hasattr(response, 'template_name'):
              response.context_data['extra_data'] = '미들웨어에서 추가된 데이터'
          return response

      def __call__(self, request):
          response = self.get_response(request)
          return response
  ```

  </details>

- [x] Django란?
  <details>
    <summary>상세보기</summary>

  ## Django
  > **Python** 기반 웹 프레임워크

  ## 개념
  - **DRY(Don’t Repeat Yourself)** 원칙
      - 코드 중복을 최소화
  - 보안, 관리자기능, Auth 등 기능 제공
  - 풍부한 레퍼런스의 검증된 프레임워크

  ## Django 디자인 패턴
  - **MVC** 패턴의 변형
      
  ### MVC 디자인 패턴
  - **Model** : 데이터와 관련된 로직을 관리
  - **View** : 레이아웃과 관련된 화면을 처리
  - **Controller** : Model과 View를 연결하는 로직을 처리

  ### Django MTV Pattern
  - **View** 의 역할에 주의

  **MVC vs MTV**

  | MVC | MTV |
  | --- | --- |
  | Model | Model |
  | View | Template |
  | Controller | View |

  - **Model**
      - 데이터와 관련된 로직을 처리
  - **Template**
      - 레이아웃과 화면상의 로직을 처리      
  - **View**
      - 메인 비지니스 로직을 담당
      - 클라이언트의 요청에 대해 처리를 분기하는 역할

  </details>

**JWT 기본 이해**
- [x] JWT란 무엇인가요?
  <details>
    <summary>상세보기</summary>

  ## JSON Web Token
  - 일정한 규칙을 가지고 있고 간단한 서명을 더한 문자열
  - 토큰 자체에 유저에 대한 간단한 정보가 들어있는 형태입니다.
  - **Session DB**나 인증을 위한 여러가지 로직 처리가 불필요          

  ### 처리방식
  - ID/PW를 서버로 전송
  - 서버에서 ID/PW를 검증
    - 유효한 경우 일정한 형식으로 서명 처리된 **Token**응답
  - 이후 클라이언트는 모든 요청 **Header**에 토큰을 담아 서버로 요청을 전송
  - 서버는 해당 토큰의 유효성을 검증하고 유저의 신원과 권한을 확인 후 요청을 처리

  ### 구조
  - **HEADER**
      - 토큰의 타입 또는 서명 부분의 생성에 어떤 알고리즘이 사용되었는지 등을 저장

  - **PAYLOAD**
      - 유저 정보: 토근 발급자, 토큰 대상자, 토큰 만료시간, 활성날짜, 발급시간 등
      - 민감한 정보 제외 최소의 정보만 저장 : **User, PK** 등
      - **Claim** : **Key-Value** 형태로 구성

  - **SIGNATURE**
      - `HEADER + PAYLOAD + 서버의 비밀키` : **HEADER**에 명시된 암호 알고리즘 방식으로 생성한 값
      - 서명의 유효여부 + 유효기간 내의 토큰인지 확인하여 인증

  ### Token

  #### Access Token

  - 인증을 위해 헤더에 포함
  - 매 요청 포함 / 보안 취약
    - 짧은 만료기간 : 탈취되어도 만료되어 사용 불가

  #### Refresh Token
  - 새로 **Access Token**을 발급받기 위한 **Token**
  - **Access Token** 보다 긴 유효기간
    - 주로 사용자의 기기에 저장
    - **Refresh Token** 만료 시 재인증
  - **BlackList** : 탈취를 보완하기 위해 **DB** 리소스를 사용

  ### accounts

  #### `simplejwt`
  - `pip install djangorestframework-simplejwt`

  #### `settings`
  - `ROTATE_REFRESH_TOKENS` : 엑세스 토큰을 갱신 한 후 리프레시 토큰도 갱신
    - `BLACKLIST_AFTER_ROTATION` : 갱신 후 사용된 토큰은 블랙리스트로 관리하여 보안 강화

  ```py
  INSTALLED_APPS = [
      ...
      'rest_framework',
      'rest_framework_simplejwt.token_blacklist',
      ...
  ]

  # Custom User Model
  AUTH_USER_MODEL = 'accounts.User'

  # JMT
  REST_FRAMEWORK = {
      "DEFAULT_AUTHENTICATION_CLASSES": [
          "rest_framework_simplejwt.authentication.JWTAuthentication",
      ],
  }

  from datetime import timedelta

  SIMPLE_JWT = {
      "ACCESS_TOKEN_LIFETIME": timedelta(minutes=1),
      "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
      "ROTATE_REFRESH_TOKENS": True,
      "BLACKLIST_AFTER_ROTATION": True,
  }
  ```

  </details>

### 시나리오 설계 및 코딩 시작!

**토큰 발행과 유효성 확인**
- [x] Access / Refresh Token 발행과 검증에 관한 테스트 시나리오 작성하기
  <details>
    <summary>상세보기</summary>

  ## 테스트 시나리오

  ### Access Token 및 Refresh Token 추출
  - **테스트 메서드**: `test_access_token_and_refresh_token_extraction`
  - **목적**: 
    - 로그인 요청을 통해 Access Token과 Refresh Token을 성공적으로 생성하고 추출할 수 있는지 확인
    - `RefreshToken` 클래스를 사용하여 Access Token과 Refresh Token을 올바르게 파싱할 수 있는지 검증
  - **예상 결과**:
    - 로그인 응답 상태 코드가 `200 OK`
    - Access Token과 Refresh Token이 유효하게 생성됨

  ### Access Token 유효성 검증 성공
  - **테스트 메서드**: `test_access_token_validation_success`
  - **목적**:
    - 유효한 Access Token을 사용하여 보호된 엔드포인트에 접근했을 때 요청이 성공(`200 OK`)하는지 확인
  - **예상 결과**:
    - 보호된 엔드포인트 응답 상태 코드가 `200 OK`

  ### Access Token 유효성 검증 실패
  - **테스트 메서드**: `test_access_token_validation_failure`
  - **목적**:
    - 잘못된(유효하지 않은) Access Token으로 보호된 엔드포인트에 접근했을 때 요청이 실패(`401 Unauthorized`)하는지 확인
  - **예상 결과**:
    - 보호된 엔드포인트 응답 상태 코드가 `401 Unauthorized`

  ### Refresh Token으로 Access Token 재발급 성공
  - **테스트 메서드**: `test_refresh_token_to_access_token_success`
  - **목적**:
    - 유효한 Refresh Token으로 새로운 Access Token을 성공적으로 재발급받을 수 있는지 확인
  - **예상 결과**:
    - `/api/token/refresh/` 엔드포인트 응답 상태 코드가 `200 OK`
    - 응답 데이터에 새로운 Access Token이 포함됨

  ### Refresh Token 유효성 검증 실패
  - **테스트 메서드**: `test_refresh_token_validation_failure`
  - **목적**:
    - 잘못된(유효하지 않은) Refresh Token으로 Access Token 재발급 요청 시 실패(`401 Unauthorized`)하는지 확인
  - **예상 결과**:
    - `/api/token/refresh/` 엔드포인트 응답 상태 코드가 `401 Unauthorized`

  ### Access Token 만료 처리
  - **테스트 메서드**: `test_access_token_expiration`
  - **목적**:
    - 만료된 Access Token으로 보호된 엔드포인트에 접근했을 때 요청이 실패(`401 Unauthorized`)하는지 확인
  - **구현 상세**:
    - RefreshToken 객체를 사용하여 Access Token의 만료 시간을 강제로 과거로 설정(`set_exp(lifetime=timedelta(seconds=-1))`)
  - **예상 결과**:
    - 보호된 엔드포인트 응답 상태 코드가 `401 Unauthorized`

  ### 유효한 토큰으로 보호된 엔드포인트 접근
  - **테스트 메서드**: `test_protected_endpoint_with_valid_token`
  - **목적**:
    - 유효한 Access Token으로 보호된 엔드포인트에 접근했을 때 요청이 성공(`200 OK`)하는지 확인
  - **예상 결과**:
    - 보호된 엔드포인트 응답 상태 코드가 `200 OK`

  ### 토큰 없이 보호된 엔드포인트 접근
  - **테스트 메서드**: `test_protected_endpoint_without_token`
  - **목적**:
    - 토큰 없이 보호된 엔드포인트에 접근했을 때 요청이 실패(`401 Unauthorized`)하는지 확인
  - **예상 결과**:
    - 보호된 엔드포인트 응답 상태 코드가 `401 Unauthorized`

  </details>

**유닛 테스트 작성**
- [x] Pytest를 이용한 JWT Unit 테스트 코드 작성해보기
  <details>
    <summary>상세보기</summary>

  ```py
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
  ```

  </details>

### 백엔드 배포하기

**테스트 완성**
- [x] 백엔드 유닛 테스트 완성하기
  <details>
    <summary>상세보기</summary>

  ```py
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
  ```

  </details>

**로직 작성**
- [x] 백엔드 로직을 Django로
  <details>
    <summary>상세보기</summary>

  # Django 로직

  ##  `apps.py`
  `apps.py`는 Django 앱 설정 파일로, `ready` 메서드를 통해 앱이 로드될 때 `signals.py`를 가져옴

  ```python
  from django.apps import AppConfig

  class AccountsConfig(AppConfig):
      default_auto_field = "django.db.models.BigAutoField"
      name = "accounts"

      def ready(self):
          import accounts.signals
  ```

  ##  `custom_schema.py`
  DRF Spectacular을 사용하여 API 문서를 커스터마이징하며, 회원가입 및 로그인 API의 스키마를 정의

  ### 회원가입 스키마 (signup_schema)
  회원가입 API 요청 및 응답 구조를 정의

  ```python
  from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample
  from .serializers import SignUpSerializer, LoginSerializer

  def signup_schema(_func=None, **kwargs):
      def decorator(func):
          return extend_schema(
              tags=["사용자"],
              summary="회원가입",
              request=SignUpSerializer,
              examples=[
                  OpenApiExample(
                      "입력 예시",
                      value={
                          "username": "JIN HO",
                          "password": "12341234",
                          "nickname": "Mentos",
                      },
                      request_only=True,
                  )
              ],
              responses={
                  201: OpenApiResponse(
                      response=SignUpSerializer,
                      description="회원가입 성공. 사용자 정보와 기본 권한이 반환됩니다.",
                      examples=[
                          OpenApiExample(
                              "성공 예시",
                              value={
                                  "username": "JIN HO",
                                  "nickname": "Mentos",
                                  "roles": [{"role": "USER"}],
                              },
                              response_only=True,
                          )
                      ],
                  ),
                  400: OpenApiResponse(
                      description="잘못된 요청 처리",
                      examples=[
                          OpenApiExample(
                              "오류 예시",
                              value={
                                  "username": ["이미 존재하는 사용자명입니다."],
                                  "password": ["비밀번호는 최소 8자 이상이어야 합니다."],
                              },
                              response_only=True,
                          )
                      ],
                  ),
              },
              **kwargs
          )(func)

      return decorator if _func is None else decorator(_func)
  ```

  ### 로그인 스키마 (login_schema)
  로그인 API 요청 및 응답 구조를 정의

  ```python
  def login_schema(_func=None, **kwargs):
      def decorator(func):
          return extend_schema(
              tags=["사용자"],
              summary="로그인",
              request=LoginSerializer,
              examples=[
                  OpenApiExample(
                      "입력 예시",
                      value={"username": "JIN HO", "password": "12341234"},
                      request_only=True,
                  )
              ],
              responses={
                  200: OpenApiResponse(
                      description="로그인 성공",
                      examples=[
                          OpenApiExample(
                              "성공 예시",
                              value={
                                  "token": "eKDIkdfjoakIdkfjpekdkcjdkoIOdjOKJDFOlLDKFJKL"
                              },
                              response_only=True,
                          )
                      ],
                  ),
                  400: OpenApiResponse(description="잘못된 요청 처리"),
              },
              **kwargs
          )(func)

      return decorator if _func is None else decorator(_func)
  ```

  ##  `models.py`

  ### Role 모델
  사용자 권한을 정의하는 모델

  ```python
  from django.db import models

  class Role(models.Model):
      name = models.CharField(max_length=50, unique=True, default="USER")

      def clean(self):
          self.name = self.name.upper()

      def __str__(self):
          return self.name
  ```

  ### User 모델
  기본 `AbstractUser`를 확장하여 사용자 정보를 커스터마이징

  ```python
  from django.contrib.auth.models import AbstractUser

  class User(AbstractUser):
      username = models.CharField(max_length=150, unique=True, blank=True)
      nickname = models.CharField(max_length=50, unique=True, blank=False)
      roles = models.ManyToManyField(Role, related_name="users")

      def __str__(self):
          return self.username
  ```

  ##  `serializers.py`

  ### 회원가입 시리얼라이저 (SignUpSerializer)
  회원가입 요청 데이터를 검증하고 사용자 생성 로직을 포함

  ```python
  from rest_framework import serializers
  from .models import User, Role

  class SignUpSerializer(serializers.ModelSerializer):
      password = serializers.CharField(write_only=True)

      class Meta:
          model = User
          fields = ["username", "password", "nickname"]

      def validate_password(self, value):
          if len(value) < 8:
              raise serializers.ValidationError("비밀번호는 최소 8자 이상이어야 합니다.")
          if not any(char.isdigit() for char in value):
              raise serializers.ValidationError("비밀번호는 최소 1개의 숫자를 포함해야 합니다.")
          return value

      def create(self, validated_data):
          user = User.objects.create_user(
              username=validated_data["username"],
              password=validated_data["password"],
              nickname=validated_data["nickname"],
          )
          user.roles.add(Role.objects.get(name="USER"))
          return user
  ```

  ### 로그인 시리얼라이저 (LoginSerializer)
  로그인 요청 데이터를 검증하고 인증 로직을 포함

  ```python
  from django.contrib.auth import authenticate

  class LoginSerializer(serializers.Serializer):
      username = serializers.CharField()
      password = serializers.CharField()

      def validate(self, data):
          user = authenticate(username=data["username"], password=data["password"])
          if user is None:
              raise serializers.ValidationError("Invalid credentials")
          return user
  ```

  ##  `signals.py`
  앱 마이그레이션 후 기본 권한을 자동으로 생성하는 시그널

  ```python
  from django.db.models.signals import post_migrate
  from django.dispatch import receiver
  from .models import Role

  @receiver(post_migrate)
  def create_roles(sender, **kwargs):
      roles = ['ADMIN', 'STAFF', 'USER']
      for role in roles:
          Role.objects.get_or_create(name=role)
  ```

  ##  `views.py`

  ### 회원가입 뷰 (SignUp)
  회원가입 요청 처리 및 사용자 생성 후 역할 정보를 반환

  ```python
  from rest_framework.views import APIView
  from rest_framework.response import Response
  from rest_framework import status
  from rest_framework_simplejwt.tokens import RefreshToken
  from .serializers import SignUpSerializer, LoginSerializer
  from .custom_schema import signup_schema, login_schema

  @signup_schema
  class SignUp(APIView):
      def post(self, request, *args, **kwargs):
          serializer = SignUpSerializer(data=request.data)
          if serializer.is_valid():
              user = serializer.save()
              roles = [{"role": role.name} for role in user.roles.all()]
              return Response({
                  'username': user.username,
                  'nickname': user.nickname,
                  'roles': roles,
              }, status=status.HTTP_201_CREATED)
          return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
  ```

  ### 로그인 뷰 (Login)
  로그인 요청 처리 및 JWT 토큰을 반환

  ```python
  @login_schema
  class Login(APIView):
      def post(self, request, *args, **kwargs):
          serializer = LoginSerializer(data=request.data)
          if serializer.is_valid():
              user = serializer.validated_data
              refresh = RefreshToken.for_user(user)
              return Response({'token': str(refresh)}, status=status.HTTP_200_OK)
          return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
  ```

  ### 보호된 뷰 (protected_view)
  인증된 사용자만 접근 가능한 엔드포인트를 제공

  ```python
  from rest_framework.decorators import api_view, permission_classes
  from rest_framework.permissions import IsAuthenticated

  @api_view(['GET'])
  @permission_classes([IsAuthenticated])
  def protected_view(request):
      return Response({'message': 'This is a protected view.'})
  ```

  ##  `urls.py`
  API 엔드포인트 정의 및 JWT 토큰 관련 경로를 추가

  ```python
  from django.urls import path
  from .views import Login, SignUp, protected_view
  from rest_framework_simplejwt import views as jwt_views

  urlpatterns = [
      path('signup/', SignUp.as_view(), name='signup'),
      path('login/', Login.as_view(), name='login'),
      path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
      path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
  ]

  urlpatterns += [
      path('protected/', protected_view, name='protected'),
  ]
  ```

  </details>

### 백엔드 배포하고 개선하기

**배포해보기**
- [x] AWS EC2에 배포하기
  <details>
    <summary>상세보기</summary>

  # Django EC2 배포

  ## EC2 인스턴스 생성
  - **AWS Management Console**에서 EC2 인스턴스를 생성
    - Ubuntu 24.04 LTS AMI 선택
    - 인스턴스 유형은 `t2.micro` 선택 (프리티어)
    - 보안 그룹 설정 시, HTTP(80), TCP(8000), SSH(22) 포트 열기

  ## Django 배포 설정
  - `settings.py`
    - `DEBUG = False`
    - `ALLOWED_HOSTS = ['<ec2-public-ip>']`

  ## 터미널을 통해 SSH 접속
  로컬 터미널에서 EC2 인스턴스에 SSH로 접속
  ```bash
  ssh -i <발급 받은 키 파일> ubuntu@<your-ec2-public-ip>
  ```

  ## 필수 패키지 설치
  ### APT 업데이트:
  ```bash
  sudo apt update
  sudo apt upgrade -y
  ```

  ### Git 설치:
  ```bash
  sudo apt install git -y
  ```

  ### Docker 설치:
  ```bash
  sudo apt install docker.io -y
  ```

  ### Docker Compose 설치:
  ```bash
  sudo apt install docker-compose -y
  ```

  ## 4. 프로젝트 클론
  Django 프로젝트를 EC2 인스턴스로 복제
  ```bash
  git clone https://github.com/<username>/<project>.git
  cd <yourproject>
  ```

  ## 5. `.env` 파일 작성 (Django Secret 설정)
  - `.env` 파일을 생성하여 Django 비밀 키, 데이터베이스 연결 정보 등을 설정
  ```bash
  sudo vim .env
  ```
  - `.env` 예시:
  ```
  DJANGO_SECRET_KEY=<secret-key>
  ```

  ## 6. Docker Compose를 이용해 서비스 시작
  `docker-compose.yml` 파일을 확인하고, 설정이 맞는지 확인한 후 아래 명령어로 서비스를 빌드하고 실행
  ```bash
  sudo docker-compose up --build -d
  ```

  </details>

**API 접근과 검증**
- [x] Swagger UI로 접속 가능하게 하기
  <details>
    <summary>상세보기</summary>

    [Swagger UI 접속](http://43.200.4.212:8000/swagger-ui/)

  </details>

**AI-assisted programming**
- [x] AI에게 코드리뷰 받아보기
  <details>
    <summary>상세보기</summary>
    
    ## coderabbitai를 활용한 PR시 코드 리뷰

    ### PR 코드 요약
    ![요약](/img/code_review_1.png)

    ### 코드 개선
    ![개선_1](/img/code_review_2.png)
    ![개선_2](/img/code_review_3.png)

  </details>

**Refactoring**
- [x] 피드백 받아서 코드 개선하기
  <details>
    <summary>상세보기</summary>

  ## AI 코드리뷰 적용

  ![반영_1](/img/refactor_1.png)
  ![반영_2](/img/refactor_2.png)

  </details>

**마무리**
- [x] AWS EC2 재배포하기



