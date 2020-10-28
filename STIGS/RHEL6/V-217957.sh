#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.

#STIG Identification
GrpID="V-217957"
GrpTitle="SRG-OS-000239"
RuleID="SV-217957r505923_rule"
STIGID="RHEL-06-000175"
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
files="\/etc\/group \/etc\/passwd \/etc\/gshadow \/etc\/shadow \/etc\/security\/opasswd"

for file in $files; do
 if ! auditctl -l | awk '/^-w '"$file"' -p wa/' >> $Results; then
  ((scorecheck+=1))
 fi
done
		
if [ "$scorecheck" != 0 ]; then
 echo "Audit Rules not found" >> $Results
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
