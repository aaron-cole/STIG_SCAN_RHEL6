#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password.

#STIG Identification
GrpID="V-218000"
GrpTitle="SRG-OS-000109"
RuleID="SV-218000r603264_rule"
STIGID="RHEL-06-000237"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^PermitRootLogin" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PermitRootLogin/ {
	if($2 == "no") {
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
