#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling the "bluetooth" service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range.

#STIG Identification
GrpID="V-218064"
GrpTitle="SRG-OS-000095"
RuleID="SV-218064r603264_rule"
STIGID="RHEL-06-000331"
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
echo "Startup Status - $(chkconfig bluetooth --list 2>> $Results)" >> $Results

if [ "$(chkconfig bluetooth --list 2>>/dev/null  | grep -e "\<[1-5]\>:on")" ] ; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
