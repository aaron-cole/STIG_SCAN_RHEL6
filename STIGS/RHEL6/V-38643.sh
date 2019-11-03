#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Data in world-writable files can be modified by any user on the system. In almost all circumstances, files can be configured using a combination of user and group permissions to support whatever legitimate access is needed without the risk caused by world-writable files.

#STIG Identification
GrpID="V-38643"
GrpTitle="SRG-OS-999999"
RuleID="SV-50444r3_rule"
STIGID="RHEL-06-000282"
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
pubfiles="$(find / -type f -not -path "/proc/*" -perm 002 2>/dev/null)"

if [ -n "$pubfiles" ]; then
 echo "$pubfiles" >> $Results
 echo "Fail" >> $Results 
else
 echo "No world-writable files found" >> $Results 
 echo "Pass" >> $Results
fi

