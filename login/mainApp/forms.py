from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import (
    authenticate,
    get_user_model

)
User = get_user_model()

class UserLoginForm(forms.Form):
    username = forms.CharField(widget= forms.TextInput(attrs={'class':'login-username','placeholder':'Username'}),label="")
    password= forms.CharField(widget=forms.PasswordInput(attrs={'class':'login-password','placeholder':'Password'}),label="")
    def clean(self, *args, **kwargs):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        if username and password:
            user = authenticate(username=username,password=password)
            if not user:
                raise forms.ValidationError('Eclatax')
            if not user.check_password(password):
                raise forms.ValidationError('Your password is incorrect')
            if not user.is_active:
                raise forms.ValidationError('User not activated')
        return super(UserLoginForm, self).clean(*args,**kwargs)


class UserRegisterForm(UserCreationForm):
    username = forms.CharField(widget= forms.TextInput(attrs={'class':'login-username','placeholder':'Username'}),label="")
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={'class':'login-password','placeholder':'Password'}),label="")
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={'class':'login-password','placeholder':'Repeat Password'}),label="")

    class Meta:
        model = User
        fields = ['username','password1', 'password2']
