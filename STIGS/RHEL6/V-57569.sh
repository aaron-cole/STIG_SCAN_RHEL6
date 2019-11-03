#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Allowing users to execute binaries from world-writable directories such as "/tmp" should never be necessary in normal operation and can expose the system to potential compromise.

#STIG Identification
GrpID="V-57569"
GrpTitle="SRG-OS-999999"
RuleID="SV-71919r1_rule"
STIGID="RHEL-06-000528"
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

if grep "/tmp " /etc/fstab | grep noexec >> $Results; then
 echo "Pass" >> $Results
else
 grep "/tmp " /etc/fstab >> $Results
 echo "Fail" >> $Results
fi
