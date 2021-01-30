#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.

#STIG Identification
GrpID="V-217981"
GrpTitle="SRG-OS-000096"
RuleID="SV-217981r603264_rule"
STIGID="RHEL-06-000203"
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

echo "Running Status - $(service xinetd status 2>> $Results)" >> $Results 2>> $Results
echo "Startup Status - $(chkconfig xinetd --list 2>> $Results)" >> $Results 2>>$Results

if [ "$(service xinetd status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig xinetd --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
