#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#This ensures a user login will be terminated as soon as the "ClientAliveCountMax" is reached.

#STIG Identification
GrpID="V-217997"
GrpTitle="SRG-OS-000126"
RuleID="SV-217997r603264_rule"
STIGID="RHEL-06-000231"
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
if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^ClientAliveCountMax" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^ClientAliveCountMax/ {
	if($2 == 0) {
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
