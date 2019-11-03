#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Group-ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.

#STIG Identification
GrpID="V-38453"
GrpTitle="SRG-OS-999999"
RuleID="SV-50253r2_rule"
STIGID="RHEL-06-000517"
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

if grep "^......G" $TempDIR/RPMVA_status >> $Results; then
 echo "Fail" >> $Results
else
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
