#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Unique usernames allow for accountability on the system.

#STIG Identification
GrpID="V-218044"
GrpTitle="SRG-OS-000121"
RuleID="SV-218044r505923_rule"
STIGID="RHEL-06-000296"
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

if pwck -rq >> $Results; then 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
