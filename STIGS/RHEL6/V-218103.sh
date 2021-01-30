#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Each process on the system carries an "auditable" flag which indicates whether its activities can be audited. Although "auditd" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot.

#STIG Identification
GrpID="V-218103"
GrpTitle="SRG-OS-000062"
RuleID="SV-218103r603264_rule"
STIGID="RHEL-06-000525"
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

if grep $(uname -r) /boot/grub/grub.conf | grep kernel | grep "audit=1" >> $Results; then
 echo "Pass" >> $Results
elif grep $(uname -r) /boot/efi/EFI/redhat/grub.conf | grep kernel | grep "audit=1" >> $Results; then
 echo "Pass" >> $Results
else
 grep $(uname -r) /boot/grub/grub.conf | grep kernel >> $Results
 echo "Fail" >> $Results
fi
