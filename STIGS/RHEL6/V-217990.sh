#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling the "ypbind" service ensures the system is not acting as a client in a NIS or NIS+ domain.

#STIG Identification
GrpID="V-217990"
GrpTitle="SRG-OS-000096"
RuleID="SV-217990r505923_rule"
STIGID="RHEL-06-000221"
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

echo "Running Status - $(service ypbind status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig ypbind --list 2>> $Results)" >> $Results

if [ "$(service ypbind status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig ypbind --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
