#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Ensuring the validity of packages' cryptographic signatures prior to installation ensures the provenance of the software and protects against malicious tampering.

#STIG Identification
GrpID="V-217855"
GrpTitle="SRG-OS-000366"
RuleID="SV-217855r603264_rule"
STIGID="RHEL-06-000013"
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

if [ -f /etc/yum.conf ]; then
#Not Going to process any more than 1 lines
#Check will fail automatically if set twice
 if [ -e /etc/yum.conf ] && [ "$(grep "^gpgcheck" /etc/yum.conf | wc -l)" -eq 1 ]; then 
 awk -v opf="$Results" -F= '/^gpgcheck/ {
	if($2 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/yum.conf
 else
  echo "Setting not defined or more than 1 configuration" >> $Results 
  echo "Fail" >> $Results
 fi
else
 echo "/etc/yum.conf does not exist" >> $Results
 echo "Pass" >> $Results
fi
