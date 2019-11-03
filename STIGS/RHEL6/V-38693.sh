#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.

#STIG Identification
GrpID="V-38693"
GrpTitle="SRG-OS-999999"
RuleID="SV-50494r4_rule"
STIGID="RHEL-06-000299"
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

awk '/^password.*[required|requisite].*pam_cracklib.so/' /etc/pam.d/system-auth >> $Results
awk '/^password.*[required|requisite].*pam_cracklib.so/' /etc/pam.d/password-auth >> $Results

if [ "$(awk '/^password.*[required|requisite].*pam_cracklib.so.*maxrepeat=3/' /etc/pam.d/system-auth)" ]; then
 if [ "$(awk '/^password.*[required|requisite].*pam_cracklib.so.*maxrepeat=3/' /etc/pam.d/password-auth)" ]; then
  echo "Pass" >> $Results
 else
  echo "/etc/pam.d/password-auth not configured correctly" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/etc/pam.d/system-auth not configured correctly" >> $Results
 echo "Fail" >> $Results
fi