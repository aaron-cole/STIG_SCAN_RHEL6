#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.

#STIG Identification
GrpID="V-81445"
GrpTitle="SRG-OS-000368-GPOS-00154"
RuleID="SV-96159r1_rule"
STIGID="RHEL-06-000530"
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

if grep "/dev/shm" /etc/fstab | grep -v "^#" | grep nodev >> $Results; then
 if mount | grep "on /dev/shm " | grep nodev >> $Results; then
  echo "Pass" >> $Results
 else
  echo "/dev/shm is not mounted with the nodev option" >> $Results
  echo "Fail" >> $Results
 fi
else
 echo "/dev/shm is NOT present with the nodev option in /etc/fstab" >> $Results
 echo "Fail" >> $Results
fi