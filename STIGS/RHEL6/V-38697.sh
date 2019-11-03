#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-38697"
GrpTitle="SRG-OS-999999"
RuleID="SV-50498r2_rule"
STIGID="RHEL-06-000336"
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
pubdirs="$(find / -type d -perm -002 \! -perm -1000 2>/dev/null)"

if [ -n "$pubdirs" ]; then
 echo "$pubdirs" >> $Results
 echo "Fail" >> $Results 
else
 echo "No world-writable directories with out the Sticky BIT found" >> $Results 
 echo "Pass" >> $Results
fi


