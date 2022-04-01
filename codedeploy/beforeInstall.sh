#!/bin/bash
CODEDEPLOY_BIN="/opt/codedeploy-agent/bin/codedeploy-agent"
$CODEDEPLOY_BIN stop
yum erase codedeploy-agent -y


cd /home/ec2-user/
sudo rm -rf webservice

sudo mkdir webservice
sudo yum -y update

# Python dependencies
# sudo yum -y install epel-release
sudo yum install -y python3
sudo yum install -y python3-pip

sudo yum install -y unzip