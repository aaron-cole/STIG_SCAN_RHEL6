#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account.

#STIG Identification
GrpID="V-38494"
GrpTitle="SRG-OS-000109"
RuleID="SV-50295r1_rule"
STIGID="RHEL-06-000028"
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

if  grep "^ttyS[0-9]" /etc/securetty >> $Results; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi