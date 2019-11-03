#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "atd" service could be used by an unsophisticated insider to carry out activities outside of a normal login session, which could complicate accountability. Furthermore, the need to schedule tasks with "at" or "batch" is not common.

#STIG Identification
GrpID="V-38641"
GrpTitle="SRG-OS-000096"
RuleID="SV-50442r3_rule"
STIGID="RHEL-06-000262"
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

echo "Running Status - $(service atd status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig atd --list 2>> $Results)" >> $Results

if [ "$(service atd status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig atd --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi