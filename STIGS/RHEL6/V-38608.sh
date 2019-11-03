#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.

#STIG Identification
GrpID="V-38608"
GrpTitle="SRG-OS-000163"
RuleID="SV-50409r1_rule"
STIGID="RHEL-06-000230"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^ClientAliveInterval" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^ClientAliveInterval/ {
	if($2 == 900) {
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
