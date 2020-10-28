#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-217984"
GrpTitle="SRG-OS-000095"
RuleID="SV-217984r505923_rule"
STIGID="RHEL-06-000211"
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

echo "Running Status - $(service telnet status 2>> $Results)" >> $Results 2>> $Results
echo "Startup Status - $(chkconfig telnet --list 2>> $Results)" >> $Results 2>>$Results

if [ "$(service telnet status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig telnet --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
