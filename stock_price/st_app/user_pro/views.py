from multiprocessing import context
from multiprocessing.sharedctypes import Value
from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from django.contrib.auth import authenticate, login, logout
from .models import UserProfile
from django.core.files.storage import FileSystemStorage
from st_app import settings
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
import os
from django.contrib.auth.decorators import login_required
from datetime import datetime, timedelta
import time
import urllib
import json
from urllib.request import urlopen
from datetime import date
import pandas as pd
import _thread
import requests
import urllib.request
from requests.adapters import HTTPAdapter
from user_pro.urls import *


from user_pro import models

# Create your views here.

def user_register(request):
    if request.method=='POST':
        fname = request.POST.get('firstname')
        lname = request.POST.get('lastname')
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        print(fname, lname, uname, email, pass1, pass2)
        if pass1 != pass2:
            messages.warning(request, 'Password does not match...!')
            return render(request,'index.html')

        elif User.objects.filter(username=uname).exists():
            messages.warning(request, 'This username already exists')
            return render(request,'index.html')

        elif User.objects.filter(email=email).exists():
            messages.warning(request, 'This email already exists')
            return render(request,'index.html')
        
        else:
            #print(fname,lname,uname,email,pass1,pass2)
            user = User.objects.create_user(first_name=fname, last_name=lname, username=uname, email=email, password=pass1)
            user.first_name = fname
            user.last_name = lname
            user.is_active = False
            user.save()
            messages.success(request,'You have been registered succssfully! Please check your email to confirm your email address in order to activate your account.')

            # Welcome Email
            subject = "Welcome to Opus Sock Demo website...!!!"
            message = "Hello " + user.first_name + "!! \n" + "Welcome to Opus Stock demo !! \nThank you for visiting our website\n. We have also sent you a confirmation email, please confirm your email address. \n\nThanking You\nOpus Technology Limited"        
            from_email = settings.EMAIL_HOST_USER
            to_list = [user.email]
            send_mail(subject, message, from_email, to_list, fail_silently=True)
            
            # Email Address Confirmation Email
            current_site = get_current_site(request)
            email_subject = "Confirm your Email @ Opus web demo Login!!"
            message2 = render_to_string('auth/email_confirmation.html',{
                
                'name': user.first_name,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user)
            })
            email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user.email],
            )
            email.fail_silently = True
            email.send()
            
            #messages.success(request,'You have been registered succssfully!')
            #return redirect('index')
            return render(request,'index.html')
        return render(request,'index.html')
            
    


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        user = None

    if user is not None and generate_token.check_token(user,token):
        user.is_active = True
        # user.profile.signup_confirmation = True
        user.save()
        login(request,user)
        messages.success(request, "Your Account has been activated!!")
        return render(request,'index.html')
    else:
        return render(request,'auth/activation_failed.html')
    

def user_login(request):
    if request.method=='POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return render(request,'index.html')
        else:
            messages.warning(request, 'invalid value! Please register first or try again...')
            return render(request,'index.html')
    

def user_logout(request):
    logout(request)
    return render(request,'index.html')


@login_required
def user_profile(request, user_id):
	if request.method == 'POST':
		user_obj = User.objects.get(id=user_id)
		user_profile_obj = UserProfile.objects.get(id=user_id)
		# try:
		user_img = request.FILES['user_img']
		fs_handle = FileSystemStorage()
		img_name = 'images/user_{0}.png'.format(user_id)
		if fs_handle.exists(img_name):
			fs_handle.delete(img_name)
		fs_handle.save(img_name, user_img)
		user_profile_obj.profile_img = img_name
		user_profile_obj.save()
		user_profile_obj.refresh_from_db()
		# except:
		# 	messages.add_message(request, messages.ERROR, "Unable to update image..")

		return render(request, 'profile.html', {'my_profile': user_profile_obj})
	if (request.user.is_authenticated and request.user.id == user_id):
		user_obj = User.objects.get(id=user_id)
		user_profile = UserProfile.objects.get(id=user_id)

		return render(request, 'profile.html', {'my_profile': user_profile})
