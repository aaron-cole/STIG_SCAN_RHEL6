#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "root" group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.

#STIG Identification
GrpID="V-217902"
GrpTitle="SRG-OS-000480"
RuleID="SV-217902r505923_rule"
STIGID="RHEL-06-000066"
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

if [ -f /boot/grub/grub.conf ]; then
 stat -Lc %G /boot/grub/grub.conf >> $Results
 if [ `stat -Lc %G /boot/grub/grub.conf` == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
elif [ -f /boot/efi/EFI/redhat/grub.conf ]; then
 stat -Lc %G /boot/efi/EFI/redhat/grub.conf >> $Results
 if [ `stat -Lc %G /boot/efi/EFI/redhat/grub.conf` == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Unable to find grub.conf" >> $Results
 echo "Fail" >> $Results
fi
