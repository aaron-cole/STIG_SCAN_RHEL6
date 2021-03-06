#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The hashes for all user account passwords should be stored in the file "/etc/shadow" and never in "/etc/passwd", which is readable by all users.

#STIG Identification
GrpID="V-217869"
GrpTitle="SRG-OS-000073"
RuleID="SV-217869r603264_rule"
STIGID="RHEL-06-000031"
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

if cut -f 2 -d: /etc/passwd | grep -v "^x$" >> $Results; then
 echo "Fail" >> $Results
else
 echo "Hashes not found in /etc/passwd" >> $Results
 echo "Pass" >> $Results
fi
