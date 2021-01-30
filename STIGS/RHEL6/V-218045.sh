#!/bin/sh
##Automatically defined items##

#Vulnerability Discussion
#When temporary accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.

#STIG Identification
GrpID="V-218045"
GrpTitle="SRG-OS-000002"
RuleID="SV-218045r603264_rule"
STIGID="RHEL-06-000297"
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
TempDIR="./Results"

if [ -e $TempDIR/prestage ]; then
 grep "$GrpID" $TempDIR/prestage | cut -f 2 -d ":" >> $Results
 grep "$GrpID" $TempDIR/prestage | cut -f 3 -d ":" >> $Results
else
PS3="$GrpID - Do you provision Temporary Accts?"
MM=( "Yes" "No" )
 
  #MENU
select opt in "${MM[@]}" ; do
 case "$REPLY" in
    1)  echo "Yes Temporary Accounts are provisioned" >> $Results
		echo "Manual" >> $Results 
		break;;
    2)  echo "No Temporary Accounts are not provisioned" >> $Results
		echo "Pass" >> $Results
		break;;
    *) 	echo "Invalid selection, please try again" ;;
 esac
done
fi
