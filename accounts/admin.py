from django.contrib import admin
from .models import UserMFA

@admin.register(UserMFA)
class UserMFAAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_type", "hotp_counter", "issuer", "updated_at")
    search_fields = ("user__username", "issuer")