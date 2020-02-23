from django.db import models
class UserInfo( models.Model):
    username=models.CharField(max_length=32,verbose_name='用户名')
    password=models.CharField(max_length=64,verbose_name='密码')
    token=models.CharField(max_length=64,null=True,blank=True,verbose_name='token')
