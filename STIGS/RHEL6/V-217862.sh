#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The .shosts and shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

#STIG Identification
GrpID="V-217862"
GrpTitle="SRG-OS-000480"
RuleID="SV-217862r505923_rule"
STIGID="RHEL-06-000021"
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

if [ $(find / -type f \( -name "*.shosts" -o -name "shosts.equiv" \) 2>>/dev/null ) ) ] ; then 
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
