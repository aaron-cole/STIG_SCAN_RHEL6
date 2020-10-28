#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Permissions on audit binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.

#STIG Identification
GrpID="V-218030"
GrpTitle="SRG-OS-000256"
RuleID="SV-218030r505923_rule"
STIGID="RHEL-06-000278"
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

if rpm -V audit | grep "^.M" >> $Results; then 
 for fn in $(rpm -V audit | grep "^.M" | awk '{print $2}'); do 
  RPMperms="$(rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:octal}\n]" audit | grep $fn | cut -f2 -d" " | cut -c 3-)"
  if [ "$RPMperms" -gt $(stat -c %a $fn) ]; then
   echo "$fn - Install Perms: $RPMperms - Actual Perms: $(stat -c %a $fn)" >> $Results
   ((scorecheck+=1))
  fi
 done
else 
 echo "Nothing Found" >> $Results
fi

if [ "$scorecheck" != 0 ]
then
 echo "Fail" >> $Results 
else 
 echo "Pass" >> $Results
fi
