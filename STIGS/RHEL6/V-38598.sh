#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The rexec service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.

#STIG Identification
GrpID="V-38598"
GrpTitle="SRG-OS-000033"
RuleID="SV-50399r2_rule"
STIGID="RHEL-06-000216"
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

echo "Running Status - $(service rexecd status 2>> $Results)" >> $Results 2>> $Results
echo "Startup Status - $(chkconfig rexecd --list 2>> $Results)" >> $Results 2>>$Results

if [ "$(service rexecd status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig rexecd --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi