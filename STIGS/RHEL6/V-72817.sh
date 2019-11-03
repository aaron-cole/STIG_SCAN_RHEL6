#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The use of wireless networking can introduce many different attack vectors into the organization’s network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.

#STIG Identification
GrpID="V-72817"
GrpTitle="RHEL-06-000293"
RuleID="SV-87461r1_rule"
STIGID="RHEL-06-000293"
Results="./Results/$GrpID"

#Remove File if already there
[ -e $Results ] && rm -rf $Results

#Setup Results File
echo $GrpID >> $Results
echo $GrpTitle >> $Results
echo $RuleID >> $Results
echo $STIGID >> $Results
##END of Automatic Items##

###Check###

if ip addr | grep -i "wlan" >> $Results; then 
 echo "Fail" >> $Results
else
 echo "No Wireless adapaters Found" >> $Results 
 echo "Pass" >> $Results
fi