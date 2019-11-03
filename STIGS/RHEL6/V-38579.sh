#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Only root should be able to modify important boot parameters.

#STIG Identification
GrpID="V-38579"
GrpTitle="SRG-OS-999999"
RuleID="SV-50380r2_rule"
STIGID="RHEL-06-000065"
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
 stat -Lc %U /boot/grub/grub.conf >> $Results
 if [ `stat -Lc %U /boot/grub/grub.conf` == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
elif [ -f /boot/efi/EFI/redhat/grub.conf ]; then
 stat -Lc %U /boot/efi/EFI/redhat/grub.conf >> $Results
 if [ `stat -Lc %U /boot/efi/EFI/redhat/grub.conf` == "root" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Unable to find grub.conf" >> $Results
 echo "Fail" >> $Results
fi