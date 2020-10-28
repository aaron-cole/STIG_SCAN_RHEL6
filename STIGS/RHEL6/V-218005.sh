#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Approved algorithms required for compliance must impart some level of confidence in their implementation.

#STIG Identification
GrpID="V-218005"
GrpTitle="SRG-OS-000033"
RuleID="SV-218005r505923_rule"
STIGID="RHEL-06-000244"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^MACs" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
 awk -v opf="$Results" '/^MACs/ {
	if($2 == "hmac-sha2-512,hmac-sha2-256" || $2 == "hmac-sha2-256,hmac-sha2-512") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/sshd_config
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
