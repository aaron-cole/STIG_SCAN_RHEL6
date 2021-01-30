#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-224674"
GrpTitle="SRG-OS-000300"
RuleID="SV-224674r603264_rule"
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
