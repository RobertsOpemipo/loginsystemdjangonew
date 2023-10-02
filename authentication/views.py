from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from django.contrib.auth import authenticate, login, logout
from logins import settings  # Corrected import
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth import authenticate, login, logout
from . tokens import generate_token


# Create your views here.
def home(request):
    return render(request,"authentication/index.html")

def signup(request):

    if request.method == "POST":
        # username = request.POST.get('username')
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pwd = request.POST['pwd']
        cpwd = request.POST['cpwd']

        if User.objects.filter(username=username):
            messages.error(request,"Username already exists!")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request,"Email already exists")
            return redirect('home')
        
        if len(username)>10:
            messages.error(request,'Your Username is too long!')

        if pwd != cpwd:
            messages.error(request,'Passwords do not match.')

        if not username.isalnum():
            messages.error(request,'Messages must be alpha numeris')
            return redirect('home')

        myuser = User.objects.create_user(username,email,pwd)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Your account has been successfully created. We have sent confirmation to email. Confirm your account")


        #Welcome email

        subject= "Welcome to Django login!!!"
        message="Hello" + myuser.first_name + "!! \n" + "Thank you for visiting our website"
        from_email=settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently=True)


        #Email Address

        current_site = get_current_site(request)
        email_subject = "Confirm your email @ Login"
        message2 = render_to_string("email_confirmation.html"),{
            'name' : myuser.first_name,
            'domain' : current_site.domain,
            'uid' : urlsafe_b64decode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        }
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email]
        )
        email.fail_silently = True
        email.send()


        return redirect (signin)

    return render(request,"authentication/signup.html")

def signin(request): 
    if request.method == "POST":
        username = request.POST['username']
        pwd = request.POST['pwd']

        user = authenticate(username=username, password=pwd)

        if user is not None:
            login(request,user)
            fname = user.first_name
            return render(request, "authentication/index.html",{ 'fname': fname })

        else:
            messages.error(request,"Bad Credentials!!!")
            return redirect('home')

    return render(request,"authentication/signin.html")

def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')

def signout(request):
    logout(request)
    messages.success(request,"Logged out Successfully!")
    return redirect('home')
