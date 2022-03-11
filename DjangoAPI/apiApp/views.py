from django.shortcuts import render
from django.views import View
from rest_framework.response import Response
import bcrypt

import time
import base64
import hmac

# Create your views here.
from django.http import HttpResponse, JsonResponse
import json
from rest_framework.views import APIView
from sqlalchemy import true
from apiApp import models
# get_token生成加密token,out_token解密token
from apiApp.token_module import get_token,out_token
from django.contrib.auth.models import User
from django.contrib import auth
import hashlib
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.mixins import LoginRequiredMixin
from apiApp.models import UserRegister, Pic
from django.core import serializers
from django.core.validators import validate_email
import os

from datetime import datetime
from apiApp.custom_storage import MediaStorage
from django.conf import settings






userExist = ""


def testRequest(request):
    return HttpResponse(content_type='application/json; charset=utf-8 ')


# class AuthLogin(APIView):
#     def post(self,request):
#         response={"status":100,"msg":None}
#         name=request.data.get("name")
#         pwd=request.data.get("pwd")
#         print(name,pwd)
#         user=models.User.objects.filter(username=name,password=pwd).first()
#         if user:
#             # token=get_random(name)
#             # 将name进行加密,3600设定超时时间
#             token=get_token(name,60)
#             models.UserToken.objects.update_or_create(user=user,defaults={"token":token})
#             response["msg"]="登入成功"
#             response["token"]=token
#             response["name"]=user.username
#         else:
#             response["msg"]="用户名或密码错误"
#         return Response(response)

class TokenRequiredMixin(View):
    def dispatch(self, request, *args, **kwargs):
        token = request.META.get('HTTP_TOKEN')
        print(token)
        user = User.objects.filter(token = token).first()
        if not user:
            return JsonResponse({
                'code': 403,
                'message': 'error token'
            })
        else:
            return super(TokenRequiredMixin, self).dispatch(request, *args, **kwargs)


class UserViews(View):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        token = request.META.get('HTTP_TOKEN')
        print(type(token))
        global userExist
        # user = User.objects.filter(token = token).first()
        users = User.objects.all()
        for user in users:
            if user.userprofile.token == token:
                userExist = user.userprofile.token
        if userExist != token:
            return JsonResponse({
                'code': 403,
                'message': 'error token'
            })
        else:
            return super().dispatch(request, *args, **kwargs)   

    def get(self, request, *args, **kwargs):
        users = User.objects.all()
        res_list = []
        for user in users:
            res_list.append({
                'username': user.username,
                'phone':user.userprofile.phone
            })
        
        return JsonResponse({
            'code':0,
            'message':'search success',
            'content':res_list
        })

class LoginViews(View):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        pay_load = json.loads(request.body)
        username_ = pay_load.get('username')
        password_ = pay_load.get('password')
        user = auth.authenticate(username = username_, password = password_)
        if not user:
            return JsonResponse({
                'code' : 400,
                'message' : 'error password or username'
            })
        else:
            token = self.generate_token(username_)
            user.userprofile.token = token
            user.userprofile.save()
            user.save()

        return JsonResponse({
            'code' : 0,
            'message' : 'get success',
            'token': token
        })

    def generate_token(self, username):
        return hashlib.md5(username.encode('utf-8')).hexdigest()


class CreateUser(View):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        pay_load = json.loads(request.body)
        EmailAddress = pay_load.get('username')
        try:
            validate_email(EmailAddress)
        except:
            return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        if EmailAddress == None or EmailAddress == "":
            return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        else:
            Password = pay_load.get('password')
            FirstName = pay_load.get('first_name')
            LastName = pay_load.get('last_name')
            if not Password:
                Password = ""
                #return HttpResponse(content_type='application/json; charset=utf-8',status=400)

            # He = EmailAddress + ":" + Password
            # print(He)

            # basicToken = 
            salt = bcrypt.gensalt()
            hashedPassword = bcrypt.hashpw(Password.encode("utf-8"), salt)

            user = UserRegister.objects.filter(username = EmailAddress)
            # token = user.values_list('token')
            if user:
                return HttpResponse(content_type='application/json; charset=utf-8',status=400)
                # # user_ = UserRegister.objects.get(id = user)
                # flag = self.certify_token(key=EmailAddress, token=user[0].token)
                # if flag:
                #     return HttpResponse(content_type='application/json; charset=utf-8',status=400)
                #     # return JsonResponse({
                #     #     'code' : 400,
                #     #     'message' : 'error password or username'
                #     # })
                # else:
                #     token = self.generate_token(key = EmailAddress)
                #     UserRegister.objects.filter(username = EmailAddress).update(token = token)

                #     content = {
                #         'id': str(user[0].id),
                #         'first_name':user[0].first_name,
                #         'last_name': user[0].last_name,
                #         'username': user[0].username,
                #         'account_created': str(user[0].account_created),
                #         'account_updated': str(user[0].account_updated),
                #         'token': token
                #     }

                #     # return JsonResponse({
                #     #     'code' : 0,
                #     #     'message' : 'get success',
                #     #     'token': token
                #     # })   
                #     return HttpResponse(content = json.dumps(content), content_type='application/json; charset=utf-8',status=201)            

            else:

                Rawtoken = EmailAddress + ":" + str(hashedPassword)

                token = self.generate_token(key = Rawtoken)
                register = UserRegister(username=EmailAddress, first_name=FirstName, last_name=LastName, password = hashedPassword)
                register.save()

                user1 = UserRegister.objects.filter(username = EmailAddress)


                content1 = {
                    'id': str(user1[0].id),
                    'first_name':user1[0].first_name,
                    'last_name': user1[0].last_name,
                    'username': user1[0].username,
                    'account_created': str(user1[0].account_created),
                    'account_updated': str(user1[0].account_updated)
                }
                return HttpResponse(content = json.dumps(content1), content_type='application/json; charset=utf-8',status=201)  


                # return JsonResponse({
                #     'code' : 0,
                #     'message' : 'get success',
                #     'token': token
                # })


    def generate_token(self, key, expire=3600):
        ts_str = str(time.time() + expire)
        ts_byte = ts_str.encode("utf-8")
        sha1_tshexstr  = hmac.new(key.encode("utf-8"),ts_byte,'sha1').hexdigest() 
        token = ts_str+':'+sha1_tshexstr
        b64_token = base64.urlsafe_b64encode(token.encode("utf-8"))
        return b64_token.decode("utf-8")

    def certify_token(self, key, token):
        r'''
            @Args:
                key: str
                token: str
            @Returns:
                boolean
        '''
        token_str = base64.urlsafe_b64decode(token).decode('utf-8')
        token_list = token_str.split(':')
        if len(token_list) != 2:
            return False
        ts_str = token_list[0]
        if float(ts_str) < time.time():
            # token expired
            return False
        known_sha1_tsstr = token_list[1]
        sha1 = hmac.new(key.encode("utf-8"),ts_str.encode('utf-8'),'sha1')
        calc_sha1_tsstr = sha1.hexdigest()
        if calc_sha1_tsstr != known_sha1_tsstr:
            # token certification failed
            return False 
        # token certification success
        return True


class GetUpdateUser(View):

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        a = False
        token = request.META.get('HTTP_TOKEN')

        token_ = request.META.get('HTTP_AUTHORIZATION')
        basicToken_ = token_[6:]
        print(basicToken_)
        NamePsw = self.getNameAndPsw(basicToken_)
        print(NamePsw)

        global userExist

        user = UserRegister.objects.filter(username = NamePsw[0])
        if user:
            PasswordOld = user[0].password[2:-1]
            print(PasswordOld)
            print(NamePsw[1].encode("utf-8"))
            if bcrypt.checkpw(NamePsw[1].encode("utf-8"), PasswordOld.encode("utf-8")):
                print("111111111111")
                return super().dispatch(request, *args, **kwargs) 
            else:
                return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        else:
            return HttpResponse(content_type='application/json; charset=utf-8',status=400)

        # # user = User.objects.filter(token = token).first()
        # users = UserRegister.objects.all()
        # for user in users:

        #     ss = self.certify_token(key = str(user.username) + ":" + str(user.password), token = str(token))
        #     if ss:
        #         a = True
        #     # if user.token == token:
        #     #     userExist = user.token
        # if not a:
        #     return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        #     # return JsonResponse({
        #     #     'code': 403,
        #     #     'message': 'error token'
        #     # })
        # else:
        #     return super().dispatch(request, *args, **kwargs)   

    def put(self, request, *args, **kwargs):
        token = request.META.get('HTTP_TOKEN')
        # users = UserRegister.objects.filter(token = token)
        token_ = request.META.get('HTTP_AUTHORIZATION')
        basicToken_ = token_[6:]
        print(basicToken_)
        NamePsw = self.getNameAndPsw(basicToken_)
        print(NamePsw)
        


        pay_load = json.loads(request.body)
        dictKeys = pay_load.keys()
        list_ = ['first_name','last_name','password','username']
        for i in dictKeys:
            if i not in list_:
                return HttpResponse(content_type='application/json; charset=utf-8', status=400)
        EmailAddress = pay_load.get('username')
        if not EmailAddress:
            return HttpResponse(content_type='application/json; charset=utf-8', status=400)

        # user = UserRegister.objects.filter(username = NamePsw[0])
        flag = True

        # users = UserRegister.objects.all()
        # for user in users:
        #     flag = self.certify_token(key=EmailAddress + ":" + str(user.password), token=token)
        #     if flag:
        #         break




        if flag:
            user = UserRegister.objects.filter(username = NamePsw[0])
            FirstName = user[0].first_name
            LastName = user[0].last_name
            Password = user[0].password
            if pay_load.get('first_name') != None:
                FirstName = pay_load.get('first_name')
            if pay_load.get('last_name') != None:
                LastName = pay_load.get('last_name')


            # FirstName = pay_load.get('first_name')
            # LastName = pay_load.get('last_name')

            PasswordNew = pay_load.get('password')

            PasswordOld = Password[2:-1]
            print("11111111111")
            print(PasswordNew.encode("utf-8"))
            print(PasswordOld.encode("utf-8"))
            if not PasswordNew:
                PasswordNew = ""

            if bcrypt.checkpw(PasswordNew.encode("utf-8"), PasswordOld.encode("utf-8")):
                hashedPassword = PasswordOld.encode("utf-8")
            else:
                if not PasswordNew:
                    PasswordNew = ""

                salt = bcrypt.gensalt()
                hashedPassword = bcrypt.hashpw(PasswordNew.encode("utf-8"), salt)


            # if pay_load.get('first_name') != None:
            #     FirstName = pay_load.get('first_name')
            # if pay_load.get('last_name') != None:
            #     LastName = pay_load.get('last_name')
            # # if pay_load.get('password') != None:
            # #     Password = pay_load.get('password')


            # password_ = pay_load.get('password')
            # if not password_:
            #     password_ = ""
            # print(type(password_))

            # if bcrypt.checkpw(password_.encode("utf-8"), Password):
            #     hashedPassword = Password
            # else:

            #     salt = bcrypt.gensalt()
            #     hashedPassword = bcrypt.hashpw(password_.encode("utf-8"), salt)


        if flag == True:

            # salt = bcrypt.gensalt()
            # hashedPassword = bcrypt.hashpw(Password.encode("utf-8"), salt)

            UserRegister.objects.filter(username = NamePsw[0]).update(first_name = FirstName)
            UserRegister.objects.filter(username = NamePsw[0]).update(last_name = LastName)
            UserRegister.objects.filter(username = NamePsw[0]).update(password = hashedPassword)
            UserRegister.objects.filter(username = NamePsw[0]).update(account_updated = datetime.now())

            # res_list = []
            # for user in users:
            #     res_list.append({
            #         'id': user.id,
            #         'first_name':user.first_name,
            #         'last_name': user.last_name,
            #         'username': user.username,
            #         'account_created': user.account_created,
            #         'account_updated': user.account_updated
            #     })
            

            return HttpResponse(content_type='application/json; charset=utf-8', status=204)
            # return JsonResponse({
            #     'code':0,
            #     'message':'update success',
            #     # 'content':res_list
            # })
        else:
            return HttpResponse(content_type='application/json; charset=utf-8', status=400)

    def get(self, request, *args, **kwargs):
        #data = {}
        


        token_ = request.META.get('HTTP_AUTHORIZATION')
        basicToken_ = token_[6:]
        print(basicToken_)
        NamePsw = self.getNameAndPsw(basicToken_)
        print(NamePsw)
        user = UserRegister.objects.filter(username = NamePsw[0])


        # token = request.META.get('HTTP_TOKEN')
        # users = UserRegister.objects.all()
        # for user in users:
        #     if self.certify_token(key = str(user.username) + ":" + str(user.password), token = token):
        #         users = UserRegister.objects.filter(username = user.username)

        # for user in users:
        data={
            'id': str(user[0].id),
            'first_name':user[0].first_name,
            'last_name': user[0].last_name,
            'username': user[0].username,
            'account_created': str(user[0].account_created),
            'account_updated': str(user[0].account_updated)
        }
        return HttpResponse(content= json.dumps(data), content_type='application/json; charset=utf-8',status=200)



    def getNameAndPsw(self, basicToken_):
        missing_padding = 4 - len(basicToken_) % 4
        if missing_padding:
            basicToken_ += '='* missing_padding
        basicToken = str.encode(basicToken_)
        print(basicToken)
        a= base64.b64decode(basicToken).decode()
        s = a.split(':')
        return s


    def certify_token(self, key, token):
        r'''
            @Args:
                key: str
                token: str
            @Returns:
                boolean
        '''
        try:
            token_str = base64.urlsafe_b64decode(token).decode('utf-8')
            token_list = token_str.split(':')
            if len(token_list) != 2:
                return False
            ts_str = token_list[0]
            if float(ts_str) < time.time():
                # token expired
                return False
            known_sha1_tsstr = token_list[1]
            sha1 = hmac.new(key.encode("utf-8"),ts_str.encode('utf-8'),'sha1')
            calc_sha1_tsstr = sha1.hexdigest()
            if calc_sha1_tsstr != known_sha1_tsstr:
                # token certification failed
                return False 
            # token certification success
            return True
        except:
            return False



class CreatePic(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    # @method_decorator(csrf_exempt)
    # def dispatch(self, request, *args, **kwargs):
    #     a = False
    #     token = request.META.get('HTTP_TOKEN')
        
    #     global userExist
    #     # user = User.objects.filter(token = token).first()
    #     users = UserRegister.objects.all()
    #     for user in users:
    #         ss = self.certify_token(key = str(user.username) + ":" + str(user.password), token = str(token))
    #         if ss:
    #             a = True
    #         # if user.token == token:
    #         #     userExist = user.token
    #     if not a:
    #         return HttpResponse(content_type='application/json; charset=utf-8',status=400)
    #         # return JsonResponse({
    #         #     'code': 403,
    #         #     'message': 'error token'
    #         # })
    #     else:
    #         return super().dispatch(request, *args, **kwargs) 

    def post(self, request, *args, **kwargs):

        token_ = request.META.get('HTTP_AUTHORIZATION')
        basicToken_ = token_[6:]
        print(basicToken_)
        NamePsw = self.getNameAndPsw(basicToken_)
        print(NamePsw)

        global userExist

        user = UserRegister.objects.filter(username = NamePsw[0])
        if user:
            PasswordOld = user[0].password[2:-1]
            print(PasswordOld)
            print(NamePsw[1].encode("utf-8"))
            if bcrypt.checkpw(NamePsw[1].encode("utf-8"), PasswordOld.encode("utf-8")):

                user_id = str(user[0].id)

                img = request.FILES['face']
                print(img)

                file_obj = request.FILES.get('face', '')
                file_directory_within_bucket = '{username}'.format(username=user_id)
                file_path_within_bucket = os.path.join(
                    file_directory_within_bucket,
                    file_obj.name
                )
                media_storage = MediaStorage()
                if not media_storage.exists(file_path_within_bucket): # avoid overwriting existing file
                    media_storage.save(file_path_within_bucket, file_obj)


                pciUrl = settings.AWS_STORAGE_BUCKET_NAME + '/' + str(user_id) + '/' + str(file_obj.name)



                print(user_id)
                pic = Pic(user_id=user_id, file_name=img, url=pciUrl)
                pic.save()

                Pic1 = Pic.objects.filter(user_id = user_id)

                content1 = {
                    'file_name': str(Pic1[0].file_name),
                    'id':str(Pic1[0].id),
                    'url': Pic1[0].url,
                    'upload_date': str(Pic1[0].upload_date),
                    'user_id': str(Pic1[0].user_id)
                }
                return HttpResponse(content = json.dumps(content1), content_type='application/json; charset=utf-8',status=201) 

                # return super().dispatch(request, *args, **kwargs) 
            else:
                return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        else:
            return HttpResponse(content_type='application/json; charset=utf-8',status=400)


                






        # token = request.META.get('HTTP_TOKEN')

        # a = False
        
        # global userExist
        # # user = User.objects.filter(token = token).first()
        # users = UserRegister.objects.all()
        # for user in users:
        #     ss = self.certify_token(key = str(user.username) + ":" + str(user.password), token = str(token))
        #     if ss:
        #         a = True
        #     # if user.token == token:
        #     #     userExist = user.token
        # if not a:
        #     return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        
        # else:

        #     users = UserRegister.objects.all()
        #     for user in users:
        #         flag = self.certify_token(key=str(user.username) + ":" + str(user.password), token=token)
        #         user_id = str(user.id)
        #         if flag:
        #             break
        #     if flag:

        #         print("aaaaaaaaaaaaaaaaaaaa")

        #         img = request.FILES['face']
        #         print(img)
        #         # 动态创建客户端上传数据的文件夹
        #         upload_folder = 'upload'
        #         # 判断是否存在该文件夹
        #         if not os.path.exists(upload_folder):
        #             # 动态创建文件夹
        #             os.mkdir(upload_folder)
        #         print("aaaaaaaaaawwwwwwwwww")
                

        #         # 获取客户端上传的文件
        #         upload_file = request.FILES.get('face', None)
        #         # 判断上传文件是否正常获取
        #         if not upload_file:
        #             return HttpResponse(content_type='application/json; charset=utf-8',status=400)
        #         # 打开文件二进制写操作
        #         destination = open(os.path.join(upload_folder, upload_file.name), 'wb+')
        #         pciUrl = os.path.join(upload_folder, upload_file.name)
        #         # 分块写入数据
        #         for chunk in upload_file.chunks():
        #             destination.write(chunk)  # 写入文件块数据
        #         # 关闭文件操作指针
        #         destination.close()
        #         print(user_id)
        #         pic = Pic(user_id=user_id, file_name=img, url=pciUrl)
        #         pic.save()
        #         print("1222222222")

        #         Pic1 = Pic.objects.filter(user_id = user_id)

        #         content1 = {
        #             'file_name': str(Pic1[0].file_name),
        #             'id':str(Pic1[0].id),
        #             'url': Pic1[0].url,
        #             'upload_date': str(Pic1[0].upload_date),
        #             'user_id': str(Pic1[0].user_id)
        #         }
        #         return HttpResponse(content = json.dumps(content1), content_type='application/json; charset=utf-8',status=201) 

    @method_decorator(csrf_exempt)
    def delete(self, request, *args, **kwargs):

        token = request.META.get('HTTP_TOKEN')





        a = False

        token_ = request.META.get('HTTP_AUTHORIZATION')
        basicToken_ = token_[6:]
        print(basicToken_)
        NamePsw = self.getNameAndPsw(basicToken_)
        print(NamePsw)


        user = UserRegister.objects.filter(username = NamePsw[0])
        print("here")
        if not user:
            return HttpResponse(content_type='application/json; charset=utf-8',status=401)


        PasswordOld = user[0].password[2:-1]
        print(PasswordOld)
        print(NamePsw[1].encode("utf-8"))
        if bcrypt.checkpw(NamePsw[1].encode("utf-8"), PasswordOld.encode("utf-8")):
            a = True

        if not a:
            return HttpResponse(content_type='application/json; charset=utf-8',status=401)
        
        else:
            # token = request.META.get('HTTP_TOKEN')
            # print("1111112222111111")
            # users = UserRegister.objects.all()
            # for user in users:
            #     flag = self.certify_token(key=str(user.username) + ":" + str(user.password), token=token)
            user_id_ = str(user[0].id)
            flag = True

            if flag:
                if Pic.objects.filter(user_id = user_id_):
                    # upload_folder = 'upload/'
                    print("rrrrrrrrrrrrrrrr")

                    Pic1 = Pic.objects.filter(user_id = user_id_)
                    print(Pic1[0].file_name)

                    file_directory_within_bucket = '{username}'.format(username=user_id_)
                    file_path_within_bucket = os.path.join(
                        file_directory_within_bucket,
                        Pic1[0].file_name
                    )
                    print(file_path_within_bucket)

                    media_storage = MediaStorage()
                    if media_storage.exists(file_path_within_bucket): # avoid overwriting existing file
                        media_storage.delete(file_path_within_bucket)
                    # r = os.path.join(upload_folder, Pic1[0].file_name)
                    # print(r)
                    # if(os.path.exists(str(r))):
                    #     print("wwwwwwwwwwww")
                    #     os.remove(str(r))
                    Pic.objects.filter(user_id = user_id_).delete()
                    return HttpResponse(content_type='application/json; charset=utf-8',status=204)
                else:
                    return HttpResponse(content_type='application/json; charset=utf-8',status=404)




    @method_decorator(csrf_exempt)
    def get(self, request, *args, **kwargs):

        token = request.META.get('HTTP_TOKEN')

        a = False

        token_ = request.META.get('HTTP_AUTHORIZATION')
        basicToken_ = token_[6:]
        print(basicToken_)
        NamePsw = self.getNameAndPsw(basicToken_)
        print(NamePsw)


        user = UserRegister.objects.filter(username = NamePsw[0])
        print("here")
        if not user:
            return HttpResponse(content_type='application/json; charset=utf-8',status=404)


        PasswordOld = user[0].password[2:-1]
        print(PasswordOld)
        print(NamePsw[1].encode("utf-8"))
        if bcrypt.checkpw(NamePsw[1].encode("utf-8"), PasswordOld.encode("utf-8")):
            a = True

        if not a:
            return HttpResponse(content_type='application/json; charset=utf-8',status=404)
        
        else:
            user_id_ = str(user[0].id)
            flag = True
            if flag:

                if Pic.objects.filter(user_id = user_id_):

                    Pic1 = Pic.objects.filter(user_id = user_id_)
                    content1 = {
                        'file_name': str(Pic1[0].file_name),
                        'id':str(Pic1[0].id),
                        'url': Pic1[0].url,
                        'upload_date': str(Pic1[0].upload_date),
                        'user_id': str(Pic1[0].user_id)
                    }
                    return HttpResponse(content = json.dumps(content1), content_type='application/json; charset=utf-8',status=200) 
                else:
                    return HttpResponse(content_type='application/json; charset=utf-8',status=404)


            # try:
            #     print(user_id_)
            #     Pic1 = Pic.objects.filter(user_id = user_id_)
            #     print(Pic1)
            # except:
            #     # delete
            #     print("111111111111")
            #     return HttpResponse(content_type='application/json; charset=utf-8',status=404)
                
            # else:
            #     Pic2 = Pic.objects.filter(user_id = user_id_).delete()
            #     print(Pic2[0])
            #     return HttpResponse(content_type='application/json; charset=utf-8',status=200)



    def generate_token(self, key, expire=3600):
        ts_str = str(time.time() + expire)
        ts_byte = ts_str.encode("utf-8")
        sha1_tshexstr  = hmac.new(key.encode("utf-8"),ts_byte,'sha1').hexdigest() 
        token = ts_str+':'+sha1_tshexstr
        b64_token = base64.urlsafe_b64encode(token.encode("utf-8"))
        return b64_token.decode("utf-8")

    def certify_token(self, key, token):
        r'''
            @Args:
                key: str
                token: str
            @Returns:
                boolean
        '''
        token_str = base64.urlsafe_b64decode(token).decode('utf-8')
        token_list = token_str.split(':')
        if len(token_list) != 2:
            return False
        ts_str = token_list[0]
        if float(ts_str) < time.time():
            # token expired
            return False
        known_sha1_tsstr = token_list[1]
        sha1 = hmac.new(key.encode("utf-8"),ts_str.encode('utf-8'),'sha1')
        calc_sha1_tsstr = sha1.hexdigest()
        if calc_sha1_tsstr != known_sha1_tsstr:
            # token certification failed
            return False 
        # token certification success
        return True


    def getNameAndPsw(self, basicToken_):
        missing_padding = 4 - len(basicToken_) % 4
        if missing_padding:
            basicToken_ += '='* missing_padding
        basicToken = str.encode(basicToken_)
        print(basicToken)
        a= base64.b64decode(basicToken).decode()
        s = a.split(':')
        return s


