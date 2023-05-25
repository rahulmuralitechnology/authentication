Certainly! Here's a step-by-step process with example code for creating a user and admin authentication API using Django Rest Framework's TokenAuthentication:

Step 1: Set up your Django project

1. Create a new Django project by running the command: `django-admin startproject authentication_api`.
2. Create a new Django app within the project: `python manage.py startapp authentication`.
3. Add the `authentication` app to the `INSTALLED_APPS` list in the project's settings file (`authentication_api/settings.py`).

Step 2: Define the User and Admin models

Open the `authentication/models.py` file and define the User and Admin models. Here's an example:

```python
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    # Add your custom fields for the User model, if any
    pass

class Admin(AbstractUser):
    # Add your custom fields for the Admin model, if any
    is_admin = models.BooleanField(default=True)
```

Step 3: Configure TokenAuthentication

Open the project's settings file (`authentication_api/settings.py`) and make the following changes:

```python
INSTALLED_APPS = [
    # Other installed apps
    'rest_framework',
    'rest_framework.authtoken',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
}
```

Step 4: Create API Views

Open the `authentication/views.py` file and define the API views for user and admin authentication. Here's an example:

```python
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User, Admin

class UserLoginView(ObtainAuthToken):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = response.data.get('token')
        if token:
            user = User.objects.get(auth_token=token)
            return Response({'token': token, 'user_id': user.id})
        return response

class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            admin = Admin.objects.get(username=username, is_admin=True)
        except Admin.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=400)

        if admin.check_password(password):
            token, _ = Token.objects.get_or_create(user=admin)
            return Response({'token': token.key, 'admin_id': admin.id})
        else:
            return Response({'error': 'Invalid credentials'}, status=400)
```

Step 5: Define API URLs

Open the project's `urls.py` file (`authentication_api/urls.py`) and define the URLs for user and admin authentication. Here's an example:

```python
from django.urls import path
from authentication.views import UserLoginView, AdminLoginView

urlpatterns = [
    path('api/user-login/', UserLoginView.as_view(), name='user_login'),
    path('api/admin-login/', AdminLoginView.as_view(), name='admin_login'),
]
```

Step 6: Test the API

Start the Django development server: `python manage.py runserver`. You can use a tool like cURL, Postman, or your web browser to make requests to the authentication API endpoints you defined.

For user authentication, make a POST request to `http://localhost:8000/api/user-login/` with the username and password in the request

 body.

For admin authentication, make a POST request to `http://localhost:8000/api/admin-login/` with the username and password in the request body.

Remember to adjust the URLs and other code snippets according to your project structure and requirements.

That's it! You now have a basic user and admin authentication API using TokenAuthentication in Django Rest Framework.