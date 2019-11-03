#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement.

#STIG Identification
GrpID="V-38477"
GrpTitle="SRG-OS-000075"
RuleID="SV-50277r1_rule"
STIGID="RHEL-06-000051"
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
if [ -e /etc/login.defs ] && [ "$(grep "^PASS_MIN_DAYS" /etc/login.defs | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^PASS_MIN_DAYS/ {
	if($2 == 1) {
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