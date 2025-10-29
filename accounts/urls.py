from django.urls import path
from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),         # Step 1: username+password
    path("otp/verify/", views.otp_verify_view, name="otp_verify"),  # Step 2: OTP code
    path("otp/setup/", views.otp_setup_view, name="otp_setup"),     # Choose TOTP/HOTP
    path("profile/", views.profile_view, name="profile"),
    path("logout/", views.logout_view, name="logout"),
]