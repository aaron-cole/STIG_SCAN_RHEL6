#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation.

#STIG Identification
GrpID="V-217858"
GrpTitle="SRG-OS-000445"
RuleID="SV-217858r603264_rule"
STIGID="RHEL-06-000017"
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

if grep selinux=0 /boot/grub/grub.conf >> $Results; then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi

