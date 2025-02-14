from django.db import models
from django.contrib.auth.models import AbstractUser

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class CustomUser(AbstractUser):
    nickname = models.CharField(max_length=50, unique=True, blank=False)
    roles = models.ManyToManyField(Role, related_name='users')

    def __str__(self):
        return self.username