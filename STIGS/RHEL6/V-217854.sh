#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.

#STIG Identification
GrpID="V-217854"
GrpTitle="SRG-OS-000191"
RuleID="SV-217854r603264_rule"
STIGID="RHEL-06-000011"
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

thismonth=$(date +%b); 
lastmonth=$(date +"%b" -d "-1 month"); 
if rpm -qa -last | grep $(date +%Y) | egrep "$lastmonth|$thismonth" >> $Results; then
 echo "Pass" >> $Results
else
 echo "Nothing installed in the past two months" >> $Results
 echo "Fail" >> $Results 
fi
