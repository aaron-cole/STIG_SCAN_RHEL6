#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the password warning age enables users to make the change at a practical time.

#STIG Identification
GrpID="V-217890"
GrpTitle="SRG-OS-000480"
RuleID="SV-217890r505923_rule"
STIGID="RHEL-06-000054"
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
if [ -e /etc/login.defs ] && [ "$(grep "^PASS_WARN_AGE" /etc/login.defs | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^PASS_WARN_AGE/ {
	if($2 == 7) {
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
