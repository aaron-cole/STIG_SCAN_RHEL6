#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Proper permissions ensure that only the root user can modify important boot parameters.

#STIG Identification
GrpID="V-217903"
GrpTitle="SRG-OS-000480"
RuleID="SV-217903r603264_rule"
STIGID="RHEL-06-000067"
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
 stat -Lc %a /boot/grub/grub.conf >> $Results
 if [ `stat -Lc %a /boot/grub/grub.conf` == "600" ]; then
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else
 echo "Unable to find grub.conf" >> $Results
 echo "Fail" >> $Results
fi
