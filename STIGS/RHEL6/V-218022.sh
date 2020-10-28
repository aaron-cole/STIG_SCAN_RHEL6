#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#NFS mounts should not present suid binaries to users. Only vendor-supplied suid executables should be installed to their default location on the local filesystem.

#STIG Identification
GrpID="V-218022"
GrpTitle="SRG-OS-000480"
RuleID="SV-218022r505923_rule"
STIGID="RHEL-06-000270"
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
 if [ "$(mount | grep nfs | grep nosuid | wc -l)" == "$(mount | grep nfs | wc -l)" ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else 
 echo "No NFS mounts found" >> $Results
 echo "Pass" >> $Results
fi
