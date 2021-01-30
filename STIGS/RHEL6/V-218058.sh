#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation.

#STIG Identification
GrpID="V-218058"
GrpTitle="SRG-OS-000095"
RuleID="SV-218058r603264_rule"
STIGID="RHEL-06-000315"
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

egrep -r "^install bluetooth|^install net-pf-31" /etc/modprobe.d >> $Results

if [ "$(grep -r "^install bluetooth \/bin\/true" /etc/modprobe.d)" ] && [ "$(grep -r "^install net-pf-31 /bin/true" /etc/modprobe.d/)" ]; then 
 echo "Pass" >> $Results 
else 
 echo "Fail" >> $Results
fi
