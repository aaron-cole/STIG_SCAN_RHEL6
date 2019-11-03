#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead.

#STIG Identification
GrpID="V-38671"
GrpTitle="SRG-OS-999999"
RuleID="SV-50472r1_rule"
STIGID="RHEL-06-000288"
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

if rpm -q sendmail >> $Results; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi