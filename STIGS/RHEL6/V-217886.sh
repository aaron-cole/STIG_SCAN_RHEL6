#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.

#STIG Identification
GrpID="V-217886"
GrpTitle="SRG-OS-000259"
RuleID="SV-217886r505923_rule"
STIGID="RHEL-06-000048"
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

if [ "$(find -L /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin  \! -user root)" ] ; then
 find -L /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin  \! -user root >> $Results
 echo "Fail" >> $Results 
else 
 echo "Nothing Found" >> $Results
 echo "Pass" >> $Results
fi
