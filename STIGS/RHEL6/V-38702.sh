#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log.

#STIG Identification
GrpID="V-38702"
GrpTitle="SRG-OS-000037"
RuleID="SV-50503r2_rule"
STIGID="RHEL-06-000339"
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
  if [ "grep -i "xferlog_enable=YES" >> $Results" ] && [ "grep -i "xferlog_std_format=NO" >> $Results" ] && [ "grep -i "log_ftp_protocol=YES" >> $Results" ]; then 
   echo "Pass" >> $Results; 
  else 
   echo "Fail" >> $Results 
  fi
 else 
  echo "vsftp is not installed" >> $Results
  echo "Pass" >> $Results
 fi
else
 echo "NA" >> $Results
fi