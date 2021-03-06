#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.

#STIG Identification
GrpID="V-217925"
GrpTitle="SRG-OS-000480"
RuleID="SV-217925r603264_rule"
STIGID="RHEL-06-000097"
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

sysctl net.ipv4.conf.default.rp_filter  | awk -v opf="$Results" '/^net.ipv4.conf.default.rp_filter/ {
	if($3 == 1) {
	 print $0 >> opf
	 print "Pass" >> opf
	} else {
	 print $0 >> opf
	 print "Fail" >> opf
	}
}'
