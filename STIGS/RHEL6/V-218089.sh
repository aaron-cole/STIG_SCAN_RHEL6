#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Operating system backup is a critical step in maintaining data assurance and availability. System-level information includes system-state information, operating system and application software, and licenses. Backups must be consistent with organizational recovery time and recovery point objectives.

#STIG Identification
GrpID="V-218089"
GrpTitle="SRG-OS-000480"
RuleID="SV-218089r603264_rule"
STIGID="RHEL-06-000505"
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

if ps -ef | grep -i netbackup | grep -v grep >> $Results; then
 echo "Pass" >> $Results
elif  [ "$(dmidecode | grep "Product Name" | grep "VMware")" == "VMwareVirtualPlatform" ]; then
 echo "Pass" >> $Results
else
 echo "Netbackup isn't running" >> $Results
 echo "Fail" >> $Results 
fi
