#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.

#STIG Identification
GrpID="V-218099"
GrpTitle="SRG-OS-000480"
RuleID="SV-218099r603264_rule"
STIGID="RHEL-06-000519"
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

if grep "^..5" $TempDIR/RPMVA_status | grep -v " c " >> $Results; then 
 echo "Fail" >> $Results 
else 
 echo "Nothing Found, This is good" >> $Results
 echo "Pass" >> $Results
fi
