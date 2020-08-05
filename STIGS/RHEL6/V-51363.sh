#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-51363"
GrpTitle="SRG-OS-999999"
RuleID="SV-65573r3_rule"
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

