#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#This setting will cause the system greeting banner to be used for FTP connections as well.

#STIG Identification
GrpID="V-218079"
GrpTitle="SRG-OS-000023"
RuleID="SV-218079r603264_rule"
STIGID="RHEL-06-000348"
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

if rpm -q vsftpd >> $Results; then
 if [ -e /etc/vsftpd/vsftpd.conf ]; then 
  if grep "banner_file=/etc/issue" /etc/vsftpd/vsftpd.conf >> $Results; then 
   echo "Pass" >> $Results
  else
   echo "Banner not linked to /etc/issue" >> $Results
   echo "Fail" >> $Results
  fi
 else
  echo "/etc/vsftpd/vsftpd.conf does not exist" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "NA" >> $Results
fi
