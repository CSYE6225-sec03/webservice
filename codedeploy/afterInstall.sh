#!/bin/bash

ls -a
cd opt
ls -a
cd aws
ls -a


cd /home/ec2-user/

ls -a

sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/home/ec2-user/cloudwatch-config.json \
    -s


# sudo systemctl stop tomcat.service
# sudo systemctl stop amazon-cloudwatch-agent.service

# #removing previous build ROOT folder
# sudo rm -rf /opt/tomcat/webapps/ROOT

# sudo chown tomcat:tomcat /opt/tomcat/webapps/ROOT.war

# # cleanup log files
# sudo rm -rf /opt/tomcat/logs/catalina*
# sudo rm -rf /opt/tomcat/logs/*.log
# sudo rm -rf /opt/tomcat/logs/*.txt