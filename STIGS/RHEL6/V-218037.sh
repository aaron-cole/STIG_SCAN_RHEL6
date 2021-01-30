#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Local mail delivery is essential to some system maintenance and notification tasks.

#STIG Identification
GrpID="V-218037"
GrpTitle="SRG-OS-000480"
RuleID="SV-218037r603264_rule"
STIGID="RHEL-06-000287"
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

echo "Running Status - $(service postfix status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig postfix --list 2>> $Results)" >> $Results

if [ "$(service postfix status 2>>/dev/null | grep "stopped")" ] || [ "$(chkconfig postfix --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
