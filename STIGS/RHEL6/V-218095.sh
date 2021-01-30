#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "all_squash" option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID.

#STIG Identification
GrpID="V-218095"
GrpTitle="SRG-OS-000104"
RuleID="SV-218095r603264_rule"
STIGID="RHEL-06-000515"
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

grep -v "#" /etc/exports >> $Results

if [ "$(cat /etc/exports | grep -v "#" | wc -l)" -gt "0" ]; then 
 if [ "$(grep all_squash /etc/exports | grep -v "#" | wc -l)" -gt 0 ]; then 
  echo "Fail" >> $Results
 else
  echo "Pass" >> $Results
 fi
else
 echo "No NFS Mounts found" >> $Results 
 echo "Pass" >> $Results
fi
