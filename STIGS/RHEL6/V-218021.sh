#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Legitimate device files should only exist in the /dev directory. NFS mounts should not present device files to users.

#STIG Identification
GrpID="V-218021"
GrpTitle="SRG-OS-000480"
RuleID="SV-218021r505923_rule"
STIGID="RHEL-06-000269"
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

if mount | grep nfs >> $Results; then 
 if [ "$(mount | grep nfs | grep nodev | wc -l)" == "$(mount | grep nfs | wc -l)" ]; then 
  echo "Pass" >> $Results
 else 
  echo "Fail" >> $Results
 fi
else 
 echo "No NFS mounts found" >> $Results
 echo "Pass" >> $Results
fi
