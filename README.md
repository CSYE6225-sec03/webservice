# webservice
Create API and call it ----> 200 if it is healthy

# necessory libraries

Python3.9.7
Django3.2.5

# commend to run project
1. clone the repositories
```bash
    git clone git@github.com:CSYE6225-sec03/webservice.git
```

2. Go into the DjangoAPI folder
```bash
    cd DjangoAPI
```

3. Enter commands in this folder
```bash
    python manage.py makemigrations
    python manage.py migrate
    python manage.py runserver
```

4. server start!

# unit test
Enter commands "python manage.py test" in DjangoAPI folder

# extra commends
1. open a new floder and use this to start a new Django project
```bash
    django-admin startproject your-name
```

2. create new app in a project
```bash
    python manage.py startapp your-name
```

3. create a superuser for the website
```bash
    python manage.py createsuperuser
```
