#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#For AIDE to be effective, an initial database of "known-good" information about files must be captured and it should be able to be verified against the installed files. 

#STIG Identification
GrpID="V-217859"
GrpTitle="SRG-OS-000363"
RuleID="SV-217859r505923_rule"
STIGID="RHEL-06-000018"
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

if [ -e /etc/aide.conf ]; then
 DIR=$(grep "@@define DBDIR" /etc/aide.conf | cut -d " " -f 3 )
 FILE=$(grep database=file: /etc/aide.conf | cut -d"/" -f2)
 if [ -e $DIR/$FILE ] ; then 
  ls -l $DIR/$FILE >> $Results
  echo "Pass" >> $Results
 fi
elif ps -ef | grep -i tripwire | grep -v grep >> $Results; then
 echo "Pass" >> $Results
else 
 echo "Fail" >> $Results
fi
