#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential.

#STIG Identification
GrpID="V-38605"
GrpTitle="SRG-OS-999999"
RuleID="SV-50406r2_rule"
STIGID="RHEL-06-000224"
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

echo "Running Status - $(service crond status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig crond --list 2>> $Results)" >> $Results

if [ "$(service crond status 2>>/dev/null | grep "stopped")" ] || [ "$(chkconfig crond --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi