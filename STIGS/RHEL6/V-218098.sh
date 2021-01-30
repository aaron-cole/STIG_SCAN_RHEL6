#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.

#STIG Identification
GrpID="V-218098"
GrpTitle="SRG-OS-000480"
RuleID="SV-218098r603264_rule"
STIGID="RHEL-06-000518"
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
TempDIR="./Results"

for fn in $(grep "^.M" $TempDIR/RPMVA_status | sed 's/^.............//'); do 
 if [ $(rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:octal}\n]" $(rpm -qf $fn) | grep "$fn " | cut -f2 -d" " | cut -c 3-) -gt $(stat -c %a $fn) ]; then 
  echo "" >> /dev/null
 else 
  echo "Installed Perms:$(rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:octal}\n]" $(rpm -qf $fn) | grep "$fn " | cut -f2 -d" " | cut -c 3-) - Actual Perms:$(stat -c %a---%n $fn)" >> $Results
  ((scorecheck+=1))
 fi
done

if [ "$scorecheck" != 0 ]
then
 echo "Fail" >> $Results 
else
 echo "Nothing Found" >> $Results 
 echo "Pass" >> $Results
fi
