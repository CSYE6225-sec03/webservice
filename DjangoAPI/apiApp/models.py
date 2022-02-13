from django.db import models
import uuid
import django.utils.timezone as timezone

# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    token = models.CharField(max_length=50, verbose_name="verdify token")
    phone = models.CharField(max_length=11, verbose_name="phoneMNumber")

# class UserRegisterReadOnly(models.Model):
#     id = models.UUIDField(primary_key=True)     # 创建一个主键
#     account_created = models.DateTimeField(max_length=32, null = True, editable =)  #  用户名
#     account_updated = models.DateTimeField(max_length=32, null = True)  # 密码

# class UserRegisterWriteOnly(models.Model):
#     id = models.UUIDField(primary_key=True)     # 创建一个主键
#     password = models.CharField(max_length=32, null = True)  #  用户名

class UserRegister(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)     # 创建一个主键
    first_name = models.CharField(max_length=32, null = True, blank=True)  #  用户名
    last_name = models.CharField(max_length=32, null = True, blank=True)  # 密码
    password = models.CharField(max_length=90, null = True, blank=True)  #  用户名
    username = models.EmailField(null = True)   # 邮箱
    account_created = models.DateTimeField(default = timezone.now)  #  用户名
    account_updated = models.DateTimeField(default = timezone.now)  # 密码
    # token = models.CharField(max_length=200, null = True, blank=True)