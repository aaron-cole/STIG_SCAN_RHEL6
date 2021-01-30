#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead.

#STIG Identification
GrpID="V-218038"
GrpTitle="SRG-OS-000095"
RuleID="SV-218038r603264_rule"
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
