#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The hash on important files like audit system executables should match the information given by the RPM database. Audit executables  with erroneous hashes could be a sign of nefarious activity on the system.

#STIG Identification
GrpID="V-218033"
GrpTitle="SRG-OS-000278"
RuleID="SV-218033r603264_rule"
STIGID="RHEL-06-000281"
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

if rpm -V audit | grep -v " c " >> $Results ; then 
 echo "Fail" >> $Results
else
 echo "All audit system executables match RPM database" >> $Results 
 echo "Pass" >> $Results
fi
