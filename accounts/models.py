from django.db import models
from django.contrib.auth.models import AbstractUser

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True, default="USER")

    def __str__(self):
        return self.name

class User(AbstractUser):
    username = models.CharField(max_length=150, unique=True, blank=True)
    nickname = models.CharField(max_length=50, unique=True, blank=False)
    roles = models.ManyToManyField(Role, related_name='users')

    def __str__(self):
        return self.username
    
    