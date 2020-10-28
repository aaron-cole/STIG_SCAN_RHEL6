#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.

#STIG Identification
GrpID="V-217889"
GrpTitle="SRG-OS-000076"
RuleID="SV-217889r505923_rule"
STIGID="RHEL-06-000053"
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

#Not Going to process any more than 1 lines
#Check will fail automatically if set twice
if [ -e /etc/login.defs ] && [ "$(grep "^PASS_MAX_DAYS" /etc/login.defs | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^PASS_MAX_DAYS/ {
	if($2 == 60) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}' /etc/login.defs
else
 echo "Setting not defined or more than 1 configuration" >> $Results 
 echo "Fail" >> $Results
fi
