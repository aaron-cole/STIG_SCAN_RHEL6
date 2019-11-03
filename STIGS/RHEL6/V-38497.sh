#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

#STIG Identification
GrpID="V-38497"
GrpTitle="SRG-OS-999999"
RuleID="SV-50298r3_rule"
STIGID="RHEL-06-000030"
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

if grep nullock /etc/pam.d/system-auth /etc/pam.d/password-auth | grep -v "^#" >> $Results; then
 echo "Fail" >> $Results
else
 echo "nullock setting not found" >> $Results
 echo "Pass" >> $Results
fi

