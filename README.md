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

# Instructions for setting up your instance using CloudFormation and AMI:
1. AWS Configure Quick Configuration:
    ```bash
    aws configure --profile produser
    ```

2. Creat Networking Resources:

    Default properties:
    ```bash
    aws cloudformation create-stack --stack-name vpc-2 --template-body file://csye6225-infra.json
    ```

    Custom properties:
    ```bash
    aws cloudformation create-stack --stack-name vpc-2 --template-body file://csye6225-infra.json --parameters ParameterKey=AMINAME,ParameterValue="ami-07b06f5f45dcc727b" ParameterKey=S3BucketName,ParameterValue="csye6225.dev.chunjunhu.me" ParameterKey=HostedZoneResource,ParameterValue="dev.chunjunhu.me." ParameterKey=DBPassword,ParameterValue="****" ParameterKey=DBUsername,ParameterValue="csye6225" ParameterKey=VPCNAME,ParameterValue="myVPC-2" ParameterKey=VPCCIDR,ParameterValue="10.0.0.0/16" ParameterKey=IGWNAME,ParameterValue="myIGW-2" ParameterKey=PUBLICROUTETABLENAME,ParameterValue="myPRT-2" ParameterKey=subnetNAME01,ParameterValue="subnet1-2" ParameterKey=SubnetCIDR1,ParameterValue="10.0.1.0/24" ParameterKey=subnetNAME02,ParameterValue="subnet2-2" ParameterKey=SubnetCIDR2,ParameterValue="10.0.2.0/24" ParameterKey=subnetNAME03,ParameterValue="subnet3-2" ParameterKey=SubnetCIDR3,ParameterValue="10.0.3.0/24"
    ```

3. Cleanup Networking Resources:
    ```bash
    aws cloudformation delete-stack --stack-name my-stack
    ```
