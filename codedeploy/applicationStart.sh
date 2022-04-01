#!/bin/bash

cd /home/ec2-user/webservice
ls -a

echo "522222222222222222222222"
sudo pip3 install -r requirements.txt
sudo pip3 install pymysql



# cd /home/ec2-user/


cd /home/ec2-user/webservice/DjangoAPI
sudo python3 manage.py makemigrations
sudo python3 manage.py migrate

# cd /home/ec2-user/webservice/DjangoAPI
# sudo python3 manage.py makemigrations
# sudo python3 manage.py migrate
cd /home/ec2-user/


ls -a
# webservice
sudo cp webservice.service /usr/lib/systemd/system
echo "5555555555555555555"
sudo systemctl daemon-reload
echo "666666666666666666665"
sudo systemctl enable webservice.service
echo "7777777777777777777775"
sudo systemctl start webservice.service
# sudo systemctl stop webservice.service


cd /home/ec2-user/webservice/DjangoAPI
sudo python3 manage.py makemigrations
sudo python3 manage.py migrate


