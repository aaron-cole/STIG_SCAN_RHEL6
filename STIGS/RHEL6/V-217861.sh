#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-217861"
GrpTitle="SRG-OS-000324"
RuleID="SV-217861r603264_rule"
STIGID="RHEL-06-000020"
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

if awk '/^SELINUX=enforcing/' /etc/selinux/config >> $Results; then 
 echo "Pass" >> $Results
else
 awk '/^SELINUX=/' /etc/selinux/config >> $Results
 echo "Fail" >> $Results
fi

