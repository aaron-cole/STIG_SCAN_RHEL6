#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling the "tftp" service ensures the system is not acting as a tftp server, which does not provide encryption or authentication.

#STIG Identification
GrpID="V-217992"
GrpTitle="SRG-OS-000095"
RuleID="SV-217992r603264_rule"
STIGID="RHEL-06-000223"
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

echo "Running Status - $(service tftp status 2>> $Results)" >> $Results 
echo "Startup Status - $(chkconfig tftp --list 2>> $Results)" >> $Results

if [ "$(service tftp status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig tftp --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
