#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user.

#STIG Identification
GrpID="V-38658"
GrpTitle="SRG-OS-000077"
RuleID="SV-50459r6_rule"
STIGID="RHEL-06-000274"
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

awk '/^password.*[required|requisite].*pam_pwhistory.so/' /etc/pam.d/system-auth >> $Results
awk '/^password.*[required|requisite].*pam_pwhistory.so/' /etc/pam.d/password-auth >> $Results

if [ "$(awk '/^password.*[required|requisite].*pam_pwhistory.so.*remember=[5-9]/' /etc/pam.d/system-auth)" ]; then
 if [ "$(awk '/^password.*[required|requisite].*pam_pwhistory.so.*remember=[5-9]/' /etc/pam.d/password-auth)" ]; then
  echo "Pass" >> $Results
 else
  echo "/etc/pam.d/password-auth not configured correctly" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/etc/pam.d/system-auth not configured correctly" >> $Results
 echo "Fail" >> $Results
fi