#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "ntpdate" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated.

#STIG Identification
GrpID="V-218017"
GrpTitle="SRG-OS-000096"
RuleID="SV-218017r603264_rule"
STIGID="RHEL-06-000265"
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

echo "Running Status - $(service ntpdate status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig ntpdate --list 2>> $Results)" >> $Results

if [ "$(service ntpdate status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig ntpdate --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
