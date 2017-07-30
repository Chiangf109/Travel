from __future__ import unicode_literals
from django.db import models
import bcrypt

class UserManager(models.Manager):
    def register(self, input):
        errors = []

        if len(input['first_name']) < 2:
            errors.append('Must have at least 3 characters for name')

        if len(input['username']) < 2:
            errors.append('Must have at least 3 characters for username')

        if not input['first_name'].isalpha():
            errors.append('Your name can only contain letters')

        if input['password'] != input['password_confirm']:
            errors.append('Passwords do not match. Try again')

        if len(input['password']) < 8:
            errors.append('Must have at least 8 characters for password')

        same = User.objects.filter(username=input['username'])

        if same:
            errors.append('Username already exists')

        if len(errors) == 0:
            pwHash = bcrypt.hashpw(input['password'].encode(), bcrypt.gensalt().encode())
            user = User.objects.create(first_name=input['first_name'], username=input['username'], password=pwHash)
            return (True, user)

        else:
            return (False, errors)

    def login(self, input):
        errors = []
        user = User.objects.filter(username=input['username'])
        if user.exists():
            InputPw = input['password'].encode()
            HashPw = user[0].password.encode()

            if bcrypt.checkpw(InputPw, HashPw):
                return (True, user[0])
            else:
                errors.append(("Username or password is wrong"))
        else:
            errors.append(("Username or password is wrong"))
        return (False, errors)

class User(models.Model):
    first_name = models.CharField(max_length=50)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
