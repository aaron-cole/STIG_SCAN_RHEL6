#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#A number of system services utilize email messages sent to the root user to notify system administrators of active or impending issues.  These messages must be forwarded to at least one monitored email address.

#STIG Identification
GrpID="V-218100"
GrpTitle="SRG-OS-000480"
RuleID="SV-218100r505923_rule"
STIGID="RHEL-06-000521"
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

aliasmaps="$(postconf alias_maps 2>/dev/null | cut -f2 -d":")"
if postmap -q root $aliasmaps 2>/dev/null >>$Results; then
 echo "Pass" >> $Results
else
 echo "Root messages aren't being forwarded" >> $Results
 echo "Fail" >> $Results
fi
