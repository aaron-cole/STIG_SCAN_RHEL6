#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.

#STIG Identification
GrpID="V-218053"
GrpTitle="SRG-OS-000363"
RuleID="SV-218053r603264_rule"
STIGID="RHEL-06-000307"
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

if [ "$(grep aide /etc/crontab | cut -f3,4,5 -d" ")" == "* * *" ]; then 
 echo "Pass" >> $Results
elif ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
