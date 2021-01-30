#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling RDS protects the system against exploitation of any flaws in its implementation.

#STIG Identification
GrpID="V-217936"
GrpTitle="SRG-OS-000096"
RuleID="SV-217936r603264_rule"
STIGID="RHEL-06-000126"
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

grep -r "^install rds" /etc/modprobe.d >> $Results

if [ "$(grep -r "^install rds \/bin\/true" /etc/modprobe.d)" ]; then 
 echo "Pass" >> $Results 
else 
 echo "Fail" >> $Results
fi
