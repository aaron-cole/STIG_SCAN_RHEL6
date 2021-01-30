#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.

#STIG Identification
GrpID="V-217988"
GrpTitle="SRG-OS-000095"
RuleID="SV-217988r603264_rule"
STIGID="RHEL-06-000218"
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

echo "Running Status - $(service rlogind status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig rlogind --list 2>> $Results)" >> $Results

if [ "$(service rlogind status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig rlogind --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi
