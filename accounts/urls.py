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