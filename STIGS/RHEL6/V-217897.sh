#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks.

#STIG Identification
GrpID="V-217897"
GrpTitle="SRG-OS-000021"
RuleID="SV-217897r505923_rule"
STIGID="RHEL-06-000061"
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

awk '/^auth.*pam_faillock.so.*deny=3/' /etc/pam.d/system-auth >> $Results
awk '/^auth.*pam_faillock.so.*deny=3/' /etc/pam.d/password-auth >> $Results

if [ "$(awk '/^auth.*[required|default=die].*pam_faillock.so.*deny=3/' /etc/pam.d/system-auth)" ]; then
 if [ "$(awk '/^auth.*[required|default=die].*pam_faillock.so.*deny=3/' /etc/pam.d/password-auth)" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
