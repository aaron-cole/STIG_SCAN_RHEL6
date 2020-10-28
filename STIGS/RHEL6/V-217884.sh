#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system.

#STIG Identification
GrpID="V-217884"
GrpTitle="SRG-OS-000259"
RuleID="SV-217884r505923_rule"
STIGID="RHEL-06-000046"
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
TempDIR="./Results"

if egrep " /usr/lib/| /usr/lib64/| /usr/local/lib/| /usr/local/lib64/| /lib/| /lib64" $TempDIR/RPMVA_status | grep "^.....U"  >> $Results ; then 
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
