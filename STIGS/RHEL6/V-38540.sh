#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited.

#STIG Identification
GrpID="V-38540"
GrpTitle="SRG-OS-999999"
RuleID="SV-50341r5_rule"
STIGID="RHEL-06-000182"
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
scorecheck=0
files="\/etc\/issue \/etc\/issue.net \/etc\/hosts \/etc\/sysconfig\/network"
modules="sethostname setdomainname"

for file in $files; do
 if ! auditctl -l | awk '/^-w '"$file"' -p wa/' >> $Results; then
  ((scorecheck+=1))
 fi
done

for module in $modules; do
 if ! auditctl -l | awk '/^-a always,exit -F arch=b32 -S .*[^-F key=]'"$module"'/' >> $Results; then
  ((scorecheck+=1))
 fi
 if ! auditctl -l | awk '/^-a always,exit -F arch=b64 -S .*[^-F key=]'"$module"'/' >> $Results; then
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
