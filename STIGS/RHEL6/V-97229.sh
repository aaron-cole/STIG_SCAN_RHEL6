#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government to ensure the algorithms have been tested and validated.

#STIG Identification
GrpID="V-97229"
GrpTitle="SRG-OS-000033-GPOS-00014"
RuleID="SV-106367r2_rule"
STIGID="RHEL-06-000534"
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

if rpm -q dracut-fips >> $Results; then
 echo "FIPS Startup - $(grep "fips=1" /boot/grub2/grub.cfg /boot/efi/EFI/redhat/grub.cfg 2>>/dev/null)" >> $Results
 echo "FIPS Running - $(cat /proc/sys/crypto/fips_enabled)" >> $Results
 if [ "$(grep "fips=1" /boot/grub2/grub.cfg /boot/efi/EFI/redhat/grub.cfg 2>>/dev/null)" ] && [ "$(cat /proc/sys/crypto/fips_enabled)" -eq "1" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Fail" >> $Results
fi
