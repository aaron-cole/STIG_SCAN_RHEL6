#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-38484"
GrpTitle="SRG-OS-000025"
RuleID="SV-50285r2_rule"
STIGID="RHEL-06-000507"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^PrintLastLog" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
awk -v opf="$Results" '/^PrintLastLog/ {
	if($2 == "yes") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/sshd_config
elif [ "$(grep "^PrintLastLog" /etc/ssh/sshd_config | wc -l)" -eq 0 ]; then
 echo "Setting not defined" >> $Results
 echo "Pass" >> $Results
else
 echo "More than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi