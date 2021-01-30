#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators. 

#STIG Identification
GrpID="V-218083"
GrpTitle="SRG-OS-000480"
RuleID="SV-218083r603264_rule"
STIGID="RHEL-06-000372"
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

awk '/^session.*required.*pam_lastlog.so/' /etc/pam.d/system-auth >> $Results

if [ "$(awk '/^session.*required.*pam_lastlog.so.*showfailed/' /etc/pam.d/system-auth | grep -v "silent")" ]; then
 echo "Pass" >> $Results
else
 echo "Fail" >> $Results
fi
