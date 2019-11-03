#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.

#STIG Identification
GrpID="V-38585"
GrpTitle="SRG-OS-000080"
RuleID="SV-50386r4_rule"
STIGID="RHEL-06-000068"
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
 if grep "^password --encrypted" /boot/grub/grub.conf >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
elif [ -f /boot/efi/EFI/redhat/grub.conf ]; then
 if grep "^password --encrypted " /boot/efi/EFI/redhat/grub.conf >> $Results; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Unable to find grub.conf" >> $Results
 echo "Fail" >> $Results
fi
