#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.

#STIG Identification
GrpID="V-38490"
GrpTitle="SRG-OS-000273"
RuleID="SV-50291r6_rule"
STIGID="RHEL-06-000503"
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

grep -r "^install usb-storage" /etc/modprobe.d >> $Results

if [ "$(grep -r "^install usb-storage \/bin\/true" /etc/modprobe.d)" ]; then 
 echo "Pass" >> $Results 
else 
 echo "Fail" >> $Results
fi