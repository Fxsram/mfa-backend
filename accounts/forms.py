from django import forms
from django.contrib.auth import authenticate
from .models import UserMFA, OTPType

class RegisterForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        user = authenticate(username=cleaned.get("username"), password=cleaned.get("password"))
        if not user:
            raise forms.ValidationError("Invalid credentials")
        cleaned["user_obj"] = user
        return cleaned

class OTPSetupForm(forms.Form):
    otp_type = forms.ChoiceField(choices=OTPType.choices)

class OTPVerifyForm(forms.Form):
    code = forms.CharField(max_length=10)