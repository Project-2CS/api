from django.urls import path
from .views import RegisterView, LoginView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    #  path('login', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('login/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view())

]
