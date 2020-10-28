#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. Ensuring that an administrator is involved in unlocking locked accounts draws appropriate attention to such situations.

#STIG Identification
GrpID="V-218081"
GrpTitle="SRG-OS-000480"
RuleID="SV-218081r505923_rule"
STIGID="RHEL-06-000356"
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

awk '/^auth.*pam_faillock.so.*unlock_time=*/' /etc/pam.d/system-auth >> $Results
awk '/^auth.*pam_faillock.so.*unlock_time=*/' /etc/pam.d/password-auth >> $Results

if [ "$(awk '/^auth.*[required|default=die].*pam_faillock.so.*unlock_time=604800/' /etc/pam.d/system-auth)" ]; then
 if [ "$(awk '/^auth.*[required|default=die].*pam_faillock.so.*unlock_time=604800/' /etc/pam.d/password-auth)" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
