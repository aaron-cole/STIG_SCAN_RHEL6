#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted.

#STIG Identification
GrpID="V-38618"
GrpTitle="SRG-OS-999999"
RuleID="SV-50419r2_rule"
STIGID="RHEL-06-000246"
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

echo "Running Status - $(service avahi-daemon status 2>> $Results)" >> $Results
echo "Startup Status - $(chkconfig avahi-daemon --list 2>> $Results)" >> $Results

if [ "$(service avahi-daemon status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig avahi-daemon --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi