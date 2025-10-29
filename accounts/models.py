from django.conf import settings
from django.db import models
import pyotp


class OTPType(models.TextChoices):
    NONE = "NONE", "None"
    TOTP = "TOTP", "Time-based (TOTP)"
    HOTP = "HOTP", "Counter-based (HOTP)"


class UserMFA(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="mfa")

    # Shared secret used by pyotp (base32)
    secret = models.CharField(max_length=64, blank=True, default="")

    # Which OTP is enabled for this user
    otp_type = models.CharField(max_length=8, choices=OTPType.choices, default=OTPType.NONE)

    # HOTP counter (only used when otp_type == HOTP)
    hotp_counter = models.PositiveIntegerField(default=0)

    issuer = models.CharField(max_length=64, default="PyOTP-MFA-Demo")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"MFA({self.user.username}) {self.otp_type}"

    # Helpers
    def ensure_secret(self):
        if not self.secret:
            self.secret = pyotp.random_base32() # 160-bit default
            self.save(update_fields=["secret"])

    def totp_obj(self, interval=30, digits=6):
        self.ensure_secret()
        return pyotp.TOTP(self.secret, interval=interval, digits=digits)

    def hotp_obj(self, digits=6):
        self.ensure_secret()
        return pyotp.HOTP(self.secret, digits=digits)

    def provisioning_uri(self):
        """
        Google Authenticator-compatible URI.
        Uses account name as user.username. Adjust to email if you prefer.
        """
        self.ensure_secret()
        if self.otp_type == OTPType.TOTP:
            return self.totp_obj().provisioning_uri(name=self.user.username, issuer_name=self.issuer)
        elif self.otp_type == OTPType.HOTP:
            return self.hotp_obj().provisioning_uri(name=self.user.username, issuer_name=self.issuer, initial_count=self.hotp_counter)
        return ""