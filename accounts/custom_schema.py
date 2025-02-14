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
                        "nickname": "Mentos"
                    },
                    request_only=True
                )
            ],
            responses={
                201: OpenApiResponse(
                    response=SignUpSerializer,
                    description='회원가입 성공',
                    examples=[
                        OpenApiExample(
                            "성공 예시",
                            value={
                                "username": "JIN HO",
                                "nickname": "Mentos",
                                "roles": [{"role": "USER"}]
                            },
                            response_only=True
                        )
                    ]
                ),
                400: OpenApiResponse(description='잘못된 요청 처리')
            },
            **kwargs  # 추가적인 데코레이터 인자
        )(func)
    return decorator if _func is None else decorator(_func)

def login_schema(_func=None, **kwargs):
    def decorator(func):
        return extend_schema(
            tags=["사용자"],
            summary="로그인",
            request=LoginSerializer,
            examples=[
                OpenApiExample(
                    "입력 예시",
                    value={
                        "username": "JIN HO",
                        "password": "12341234"
                    },
                    request_only=True
                )
            ],
            responses={
                200: OpenApiResponse(
                    description="로그인 성공",
                    examples=[
                        OpenApiExample(
                            "성공 예시",
                            value={"token": "eKDIkdfjoakIdkfjpekdkcjdkoIOdjOKJDFOlLDKFJKL"},
                            response_only=True
                        )
                    ]
                ),
                400: OpenApiResponse(description="잘못된 요청 처리")
            },
            **kwargs
        )(func)
    return decorator if _func is None else decorator(_func)

