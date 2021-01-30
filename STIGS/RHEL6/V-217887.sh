#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#

#STIG Identification
GrpID="V-217887"
GrpTitle="SRG-OS-000078"
RuleID="SV-217887r603264_rule"
STIGID="RHEL-06-000050"
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
scorecheck=0

if awk '/^PASS_MIN_LEN/ {if($2 >= 15) { print $0 }}' /etc/login.defs >> $Results; then
 if ! grep pam_cracklib /etc/pam.d/* | grep -v "^#" >> $Results; then
  echo "Not Definied in files in /etc/pam.d/" >> $Results
 else
  for word in $(grep pam_cracklib /etc/pam.d/* | grep -v "^#"); do 
   if [[ $word == minlen* ]]; then 
    if [[ $(echo $word | cut -f2 -d"=") -lt 15 ]]; then 
     ((scorecheck+=1))
    fi
   fi
  done
 fi
else 
 ((scorecheck+=1))
fi

if [ "$scorecheck" != 0 ]; then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
