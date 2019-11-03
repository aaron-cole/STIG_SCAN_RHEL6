#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks.

#STIG Identification
GrpID="V-38501"
GrpTitle="SRG-OS-000249"
RuleID="SV-50302r4_rule"
STIGID="RHEL-06-000357"
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

awk '/^auth.*pam_faillock.so.*fail_interval=900/' /etc/pam.d/system-auth >> $Results
awk '/^auth.*pam_faillock.so.*fail_interval=900/' /etc/pam.d/password-auth >> $Results

if [ "$(awk '/^auth.*[required|default=die].*pam_faillock.so.*fail_interval=900/' /etc/pam.d/system-auth)" ]; then
 if [ "$(awk '/^auth.*[required|default=die].*pam_faillock.so.*fail_interval=900/' /etc/pam.d/password-auth)" ]; then
  echo "Pass" >> $Results
 else
  echo "/etc/pam.d/password-auth not defined correctly" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/etc/pam.d/system-auth not defined correctly" >> $Results
 echo "Fail" >> $Results
fi
