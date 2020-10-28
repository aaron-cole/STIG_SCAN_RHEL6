#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used.

#STIG Identification
GrpID="V-217994"
GrpTitle="SRG-OS-000112"
RuleID="SV-217994r505923_rule"
STIGID="RHEL-06-000227"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^Protocol" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^Protocol/ {
	if($2 == 2) {
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
