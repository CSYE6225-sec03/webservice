#!/bin/bash

sudo yum -y update

# Python dependencies
# sudo yum -y install epel-release
sudo yum install -y python3
sudo yum install -y python3-pip

sudo yum install -y unzip