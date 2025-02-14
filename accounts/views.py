from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import SignUpSerializer, LoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken

class SignUp(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SignUpSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # 사용자 정보와 역할을 포함한 응답 반환
            roles = [{"role": role.name} for role in user.roles.all()]
            return Response({
                'username': user.username,
                'nickname': user.nickname,
                'roles': roles
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class Login(APIView):
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data

            # JWT 토큰 생성
            refresh = RefreshToken.for_user(user)

            return Response({
                'token': str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_view(request):
    # 인증된 사용자만 접근 가능
    return Response({'message': 'This is a protected view.'})