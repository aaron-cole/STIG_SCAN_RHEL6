#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-218104"
GrpTitle="SRG-OS-000480"
RuleID="SV-218104r603264_rule"
STIGID="RHEL-06-000526"
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

echo "Running Status - $(service autofs status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig autofs --list 2>> $Results)" >> $Results

if [ "$(service autofs status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig autofs --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
