#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space.

#STIG Identification
GrpID="V-217894"
GrpTitle="SRG-OS-000266"
RuleID="SV-217894r603264_rule"
STIGID="RHEL-06-000058"
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

if [ "$(awk '/^password.*[required|requisite].*pam_cracklib.so.*ocredit=-[1-9]/' /etc/pam.d/system-auth)" ]; then
 if [ "$(awk '/^password.*[required|requisite].*pam_cracklib.so.*ocredit=-[1-9]/' /etc/pam.d/password-auth)" ]; then
  echo "Pass" >> $Results
 else
  echo "/etc/pam.d/password-auth not configured correctly" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/etc/pam.d/system-auth not configured correctly" >> $Results
 echo "Fail" >> $Results
fi
