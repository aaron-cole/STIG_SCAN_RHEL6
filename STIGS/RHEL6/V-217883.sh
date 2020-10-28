#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system.

#STIG Identification
GrpID="V-217883"
GrpTitle="SRG-OS-000259"
RuleID="SV-217883r505923_rule"
STIGID="RHEL-06-000045"
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

if [ $(find -L /lib /lib64 /usr/lib /usr/lib64 -perm -022 -type f) ] ; then 
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
