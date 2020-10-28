#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full.

#STIG Identification
GrpID="V-217943"
GrpTitle="SRG-OS-000480"
RuleID="SV-217943r505923_rule"
STIGID="RHEL-06-000138"
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

echo "Logrotate Dates - $(grep logrotate /var/log/cron* | grep "$(date --date="yesterday" +%b)")" >> $Results

if [ "$(grep logrotate /var/log/cron* | grep "$(date --date="yesterday" +%b)")" ]; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi

