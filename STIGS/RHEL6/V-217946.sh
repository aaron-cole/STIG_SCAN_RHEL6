#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ensuring the "auditd" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.

#STIG Identification
GrpID="V-217946"
GrpTitle="SRG-OS-000037"
RuleID="SV-217946r603264_rule"
STIGID="RHEL-06-000154"
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

echo "Running Status - $(service auditd status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig auditd --list 2>> $Results)" >> $Results

if [ "$(service auditd status 2>>/dev/null | grep "stopped")" ] || [ "$(chkconfig auditd --list 2>>/dev/null | grep -e "\<[3-5]\>:off")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
