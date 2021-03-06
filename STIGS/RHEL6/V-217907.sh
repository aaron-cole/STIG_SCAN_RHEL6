#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-217907"
GrpTitle="SRG-OS-000030"
RuleID="SV-217907r603264_rule"
STIGID="RHEL-06-000071"
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

justneedone=0

if grep "TMOUT" /etc/profile.d/* | grep -v ":#"  >> /dev/null; then
 chkfiles="$(grep "TMOUT" /etc/profile.d/* | grep -v ":#" | cut -f 1 -d ":" | sort | uniq)"
 for chkfile in $chkfiles; do
  if grep "TMOUT=" $chkfile | grep -v "^#" | awk -F= '$2 <=900' >> $Results; then
   if grep "readonly TMOUT" $chkfile | grep -v "^#" >> $Results; then
    if grep "export TMOUT" $chkfile | grep -v "^#" >> $Results; then
	 justneedone=1
	 break
    fi
   fi
  fi
 done
 if [ "$justneedone" -eq 1 ]; then
  echo "Pass" >> $Results
 else
  echo "Fail" >> $Results
 fi
else
 echo "TMOUT setting not properly deployed in /etc/profile.d/" >> $Results
 echo "Fail" >> $Results
fi 
