import bcrypt
from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib import messages

from .models import *

def index(request):
    if "uuid" in request.session:
        return redirect('/home')

    return render(request, "loginReg.html")


def register(request):
    errors = User.objects.register_validator(request.POST)

    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        
        return redirect("/")
    
    else:
        hash_browns = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
        user = User.objects.create(
            first_name = request.POST["first_name"],
            last_name = request.POST["last_name"],
            email = request.POST["email"],
            birth_date = request.POST["birth_date"],
            password = hash_browns
        )
        request.session['uuid'] = user.id
        return redirect('/home')


def login(request):
    errors = User.objects.login_validator(request.POST)

    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        
        return redirect("/")
    else:
        user = User.objects.get(email = request.POST['email'])
        request.session['uuid'] = user.id
        return redirect('/home')


def logout(request):
    del request.session['uuid']
    return redirect("/")


def home(request):
    if "uuid" not in request.session:
        return redirect('/')
    context = {
        'logged_in_user': User.objects.get(id = request.session['uuid']),
        
    }
    return render(request, 'home.html', context)