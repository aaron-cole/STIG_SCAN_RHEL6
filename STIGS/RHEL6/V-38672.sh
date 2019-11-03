#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "netconsole" service is not necessary unless there is a need to debug kernel panics, which is not common.

#STIG Identification
GrpID="V-38672"
GrpTitle="SRG-OS-000096"
RuleID="SV-50473r2_rule"
STIGID="RHEL-06-000289"
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

echo "Running Status - $(service netconsole status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig netconsole --list 2>> $Results)" >> $Results

if [ "$(service netconsole status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig netconsole --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi