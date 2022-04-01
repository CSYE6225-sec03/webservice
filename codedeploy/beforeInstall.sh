#!/bin/bash
CODEDEPLOY_BIN="/opt/codedeploy-agent/bin/codedeploy-agent"
$CODEDEPLOY_BIN stop
sudo yum erase codedeploy-agent -y


cd /home/ec2-user/
ls -a
sudo rm -rf webservice
echo "522222222222222222222222"
ls -a

echo "111111111111111111111"
sudo mkdir webservice
cd /home/ec2-user/webservice
ls -a

sudo python3 manage.py makemigrations

sudo yum -y update

# Python dependencies
# sudo yum -y install epel-release
sudo yum install -y python3
sudo yum install -y python3-pip

sudo yum install -y unzip