from django.shortcuts import render

import  uuid
import datetime
from jwt import exceptions as jwt_exceptions
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from api import models



class Login_View(APIView):
    '''用户登录 '''
    def post(self,request,*args,**kwargs):
        print(21222)
        user=request.data.get('username')
        pwd = request.data.get('password')
        user_object=models.UserInfo.objects.filter(username=user).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名/密码错误'})

        random_string = str(uuid.uuid4())
        user_object.token=random_string
        user_object.save()
        return Response({'code': 1001, 'data': random_string})

class Order_View(APIView):
    def get(self, request, *args, **kwargs):
        token=request.query_params.get('token')
        if not token:
            return Response({'code':2000,'error':'登录成功之后才能访问'})
        user_obj=models.UserInfo.objects.filter(token=token).first()
        if not user_obj:
            return Response({'code': 2000, 'error':'token'})
        return Response('订单列表')



import  uuid
import datetime
from jwt import exceptions as jwt_exceptions
import jwt
from rest_framework.views import APIView
from rest_framework.response import Response
from api import models
salt = 'dsfhkjhiejgnvjcxhwwwwwwwwwww'
class JwtLogin_View(APIView):
    '''基于Jwt用户登录 '''
    def post(self,request,*args,**kwargs):
        user=request.data.get('username')
        pwd = request.data.get('password')
        user_object=models.UserInfo.objects.filter(username=user).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名/密码错误'})


        #构造header头部
        headers={
                "typ": "JWT",
                "alg": "HS256",
                }
        #构造payload
        payload={
              "user_id": user_object.pk,
              "user_name": user_object.username,
              "exp": datetime.datetime.utcnow() +datetime.timedelta(minutes=1)  #超时时间1分钟
            }
        #生成 web token  key=要加的盐 一定要保密啊！！
        web_token=jwt.encode(headers=headers,payload=payload,algorithm='HS256',key=salt).decode('utf-8')
        return Response({'code': 1001, 'data': web_token})

class JwtOrder_View(APIView):
    def get(self, request, *args, **kwargs):
        #获取token
        token=request.query_params.get('token')
        verified_payload=None
        msg=None
        try:
            # 解析token,得到第3段，True等于校验
            #注意啦！！加密、解密用得都是同1个盐！！！！千万不能泄露
            verified_payload=jwt.decode(token,salt,True)##
        except jwt_exceptions.ExpiredSignature:
            msg='Token已经超时'
        except jwt.DecodeError:
            msg='Token认证失败'
        except jwt.InvalidTokenError:
            msg='非法的Token'
        if not verified_payload:
            return Response({'code':1003,'error':msg})
        #获取第二段 用户自定义的信息
        print(verified_payload['user_id'],verified_payload['user_name'])
        return Response('订单列表')
