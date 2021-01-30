#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.

#STIG Identification
GrpID="V-218107"
GrpTitle="SRG-OS-000373"
RuleID="SV-218107r603264_rule"
STIGID="RHEL-06-000529"
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

if egrep "^[^#]*NOPASSWD|^[^#]*!authenticate" /etc/sudoers >> $Results; then 
 echo "Fail" >> $Results
else 
 if egrep -r "^[^#]*NOPASSWD|^[^#]*\!authenticate" /etc/sudoers.d >> $Results; then 
  echo "Fail" >> $Results
 else 
  echo "Nothing Found in /etc/sudoers or /etc/sudoers.d/ files" >> $Results
  echo "Pass" >> $Results 
 fi 
fi
