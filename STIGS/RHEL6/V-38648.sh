#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The qpidd service is automatically installed when the "base" package selection is selected during installation. The qpidd service listens for network connections which increases the attack surface of the system. If the system is not intended to receive AMQP traffic then the "qpidd" service is not needed and should be disabled or removed.

#STIG Identification
GrpID="V-38648"
GrpTitle="SRG-OS-000096"
RuleID="SV-50449r2_rule"
STIGID="RHEL-06-000267"
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

echo "Running Status - $(service qpidd status 2>>$Results)" >> $Results
echo "Startup Status - $(chkconfig qpidd --list 2>>$Results)" >> $Results

if [ "$(service qpidd status 2>>/dev/null | grep "is running")" ] || [ "$(chkconfig qpidd --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
 echo "Fail" >> $Results
else
 echo "Pass" >> $Results
fi