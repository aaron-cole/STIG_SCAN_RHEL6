#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system.

#STIG Identification
GrpID="V-217860"
GrpTitle="SRG-OS-000480"
RuleID="SV-217860r505923_rule"
STIGID="RHEL-06-000019"
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

if [ -e /etc/hosts.equiv ] || [ $(find / -type f -name ".rhosts" 2>>/dev/null) ]; then
 echo "/etc/hosts.equiv or .rhosts files found" >> $Results
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
