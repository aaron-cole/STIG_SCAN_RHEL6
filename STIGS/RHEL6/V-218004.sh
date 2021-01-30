#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-218004"
GrpTitle="SRG-OS-000033"
RuleID="SV-218004r603822_rule"
STIGID="RHEL-06-000243"
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

if [ -f /etc/ssh/sshd_config ] && [ "$(grep "^Ciphers" /etc/ssh/sshd_config | wc -l)" -eq 1 ]; then
 awk -v opf="$Results" '/^Ciphers/ {
	if($2 == "aes256-ctr,aes192-ctr,aes128-ctr") {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/ssh/sshd_config 
else
 grep "^Ciphers" /etc/ssh/sshd_config >> $Results 
 echo "Fail" >> $Results
fi
