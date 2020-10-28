#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Using the "-s" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private.

#STIG Identification
GrpID="V-218069"
GrpTitle="SRG-OS-000480"
RuleID="SV-218069r505923_rule"
STIGID="RHEL-06-000338"
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

if rpm -q tftp >> $Results; then
 echo "Running Status - $(service tftp status 2>> $Results)" >> $Results
 echo "Startup Status - $(chkconfig tftp --list 2>> $Results)" >> $Results

 if [ "$(service tftp status 2>>/dev/null | grep "is running.")" ] || [ "$(chkconfig tftp --list 2>>/dev/null | grep -e "\<[1-5]\>:on")" ] ; then 
  if grep -i "server_args = -s" /etc/xinetd.d/tftp ; then 
   echo "Pass" >> $Results
  else
   echo "Service or Startup is configured but setting not set" >> $Results
   echo "Fail" >> $Results
  fi  
 else
  echo "Service and Startup not configured or installed" >> $Results 
  echo "Pass" >> $Results
 fi
else
 echo "NA" >> $Results
fi

