#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.

#STIG Identification
GrpID="V-218001"
GrpTitle="SRG-OS-000106"
RuleID="SV-218001r603264_rule"
STIGID="RHEL-06-000239"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PermitEmptyPasswords/ {
	if($2 == "no") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/sshd_config
elif [ "$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | wc -l)" -eq 0 ]; then
 echo "Setting not defined" >> $Results
 echo "Pass" >> $Results
else
 echo "More than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi
