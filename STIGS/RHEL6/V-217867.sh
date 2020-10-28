#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system.

#STIG Identification
GrpID="V-217867"
GrpTitle="SRG-OS-000480"
RuleID="SV-217867r505923_rule"
STIGID="RHEL-06-000029"
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

if [ "$(for fn in $(egrep "x:[0-4][0-9][0-9]:|x:[0-9][0-9]:|x:[0-9]:" /etc/passwd | cut -d: -f1 | egrep -v "root|/sbin/nologin|patrol|nails|mqm"); do grep "^$fn:" /etc/shadow | cut -d: -f2 | egrep -v "^\*|\!\!|patrol|nails|mqm"; done)" ]; then
 for fn in $(egrep "x:[0-4][0-9][0-9]:|x:[0-9][0-9]:|x:[0-9]:" /etc/passwd | cut -d: -f1 | egrep -v "root|/sbin/nologin|patrol|nails|mqm"); do 
  grep "^$fn:" /etc/shadow | cut -d: -f1,2 | egrep -v "^\*|\!\!|patrol|nails|mqm" >> $Results
 done
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
