#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.

#STIG Identification
GrpID="V-38692"
GrpTitle="GEN006660"
RuleID="SV-50493r1_rule"
STIGID="RHEL-06-000334"
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

if [ -f /etc/default/useradd ] && [ "$(grep "^INACTIVE" /etc/default/useradd | wc -l)" -eq 1 ]; then
awk -v opf="$Results" -F= '/^INACTIVE/ {
	if($2 == 35) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/default/useradd
else
 echo "Setting not defined or more than 1 configuration" >> $Results
 echo "Fail" >> $Results
fi