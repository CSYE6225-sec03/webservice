from django.db import models
import uuid
import django.utils.timezone as timezone

# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    token = models.CharField(max_length=50, verbose_name="verdify token")
    phone = models.CharField(max_length=11, verbose_name="phoneMNumber")

# class UserRegisterReadOnly(models.Model):
#     id = models.UUIDField(primary_key=True)
#     account_created = models.DateTimeField(max_length=32, null = True, editable =)
#     account_updated = models.DateTimeField(max_length=32, null = True)

# class UserRegisterWriteOnly(models.Model):
#     id = models.UUIDField(primary_key=True)
#     password = models.CharField(max_length=32, null = True)

class UserRegister(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)     # id
    first_name = models.CharField(max_length=32, null = True, blank=True)  #  first_name
    last_name = models.CharField(max_length=32, null = True, blank=True)  # last_name
    password = models.CharField(max_length=90, null = True, blank=True)  #  password
    username = models.EmailField(null = True)   # username
    account_created = models.DateTimeField(default = timezone.now)  #  account_created
    account_updated = models.DateTimeField(default = timezone.now)  # account_updated
    # token = models.CharField(max_length=200, null = True, blank=True)