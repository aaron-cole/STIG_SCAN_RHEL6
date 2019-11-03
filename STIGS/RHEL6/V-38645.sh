#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.

#STIG Identification
GrpID="V-38645"
GrpTitle="SRG-OS-999999"
RuleID="SV-50446r1_rule"
STIGID="RHEL-06-000345"
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
if [ -e /etc/login.defs ] && [ "$(grep "^UMASK" /etc/login.defs | wc -l)" -eq 1 ]; then 
awk -v opf="$Results" '/^UMASK/ {
	if($2 == "077") {
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