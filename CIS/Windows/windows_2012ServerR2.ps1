
#####################
#    Information    #
#####################

# Maintainers		: Gr�gory COMMIN / Jahleel Lacascade
# Script version    : 0.8
# Script date       : January 05, 2015
# Script update		: September 13 2021

###############
#	Changelog #
###############

# v0.5 : added back Get-SharePermission function
# v0.6 : header format changed
#		redundancy removed
#		
#########
# TO-DO #
#########

###############################
#    Script initialization    #
###############################

# Verifies if the current user has administrator rights
If (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Write-Warning "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
	Break
}

# Sets encoding for correct output
cmd /C "chcp 850>nul"

#TODO path file output

# Defines constant variables
$global:logFileName = ".\output\audit.txt"

$global:authentificationFileName = ".\output\authentication.txt"
$global:networkFileName = ".\output\network.txt"
$global:systemFileName = ".\output\system.txt"
$global:encryptionFileName = ".\output\encrypte.txt"
$global:loggingFileName = ".\output\logging.txt"
$global:updatesFileName = ".\output\updates_windows.txt"
$global:securitySTFileName = ".\output\security_strategie.txt"
$global:specificPointfileName = ".\output\specific_point.txt"
$global:systemSecurefileName = ".\output\system_secure.txt"
$global:complementaryElementfileName = ".\output\complementary_element.txt"

$global:logErrorFileName = ".\output\errors.txt"
$global:secpolExportFileName = "$env:tmp\audit_secpol.txt"
$global:tempFileName = "$env:tmp\audit_temp.txt"
$global:gpresultFileName = ".\output\gpresult.html"
$global:SAMhiveFileName = ".\output\SAM"
$global:SYSTEMhiveFileName = ".\output\SYSTEM"

# Function: updates log file 
Function updateLogFile 
{
    param($fileName, $content)
    Add-Content -path "$fileName" -value $content -encoding utf8
}

# Function: inits results file
Function initResultsFile 
{
    param($content)
    
    # Write headers into results file
	If (! (Test-Path "$global:folderName\$global:outputFile")) {
		Add-Content "$global:folderName\$global:outputFile" "Local Users; Cache of domain identifiers"
	}
    # Writes results
    Add-Content "$global:folderName\$global:outputFile"  $content
}

# Function: finds name of local administrator account
Function Get-SWLocalAdmin 
{
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $ComputerName 
    )
    Process {
        Foreach ($Computer in $ComputerName) {
            Try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Computer)
                $UserPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($PrincipalContext)
                $Searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
                $Searcher.QueryFilter = $UserPrincipal
                $Searcher.FindAll() | Where-Object {$_.Sid -Like "*-500"}
            }
            Catch {
                Write-Warning -Message "$($_.Exception.Message)"
            }
        }
    }
}

# Function: finds name of local guest account
Function Get-SWLocalGuest 
{
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $ComputerName 
    )
    Process {
        Foreach ($Computer in $ComputerName) {
            Try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Computer)
                $UserPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($PrincipalContext)
                $Searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
                $Searcher.QueryFilter = $UserPrincipal
                $Searcher.FindAll() | Where-Object {$_.Sid -Like "*-501"}
            }
            Catch {
                Write-Warning -Message "$($_.Exception.Message)"
            }
        }
    }
}

# Function: gets shares permissions
Function Get-SharePermission
{
	Param(
		[String]$Server,
		[String]$ShareName
	)
	
	$ShareSecurity = Get-WMIObject win32_LogicalShareSecuritySetting -comp $Server -Filter "name='$ShareName'" 
    
	ForEach ($Share in $ShareSecurity) {
		updateLogFile $logFileName ($ShareName = $Share.Name)
		
		$ACLS = $Share.GetSecurityDescriptor().Descriptor.DACL
		
		ForEach ($ACL in $ACLS) {
			$User = $ACL.Trustee.Name
			
			Switch ($ACL.AccessMask) {
				2032127 {$Perm = "Full Control"}
				1245631 {$Perm = "Change"}
				1179817 {$Perm = "Read"}
			}
			
			$myobj = "" | Select-Object ShareName,User,Permission
			$myobj.ShareName = $ShareName
			$myobj.User = $User
			$myobj.Permission = $Perm
			$myobj
		}
	}
}

# Function: gets shares ACLs
Function Get-ShareACL 
{
	param(
		[String]$Name = "%",
		[String]$Computer = $Env:ComputerName
	)
	
	$file = New-Item $global:tempFileName -Type File -Force
	
	$Shares = @()
	
	Get-WMIObject Win32_Share -Computer $Computer -Filter "Name LIKE '$Name'" | ForEach-Object {
		$Access = @()
		
		If ($_.Type -eq 0) {
			$SD = (Get-WMIObject Win32_LogicalShareSecuritySetting -Computer $Computer -Filter "Name='$($_.Name)'").GetSecurityDescriptor().Descriptor
			$SD.DACL | ForEach-Object {
				$Trustee = $_.Trustee.Name
				If ($_.Trustee.Domain -ne $null) {
					$Trustee = "$($_.Trustee.Domain)\$Trustee"
				}
				$Access += New-Object Security.AccessControl.FileSystemAccessRule(
				$Trustee, $_.AccessMask, $_.AceType)
			}
		}
		
		$shareDescription = $_ | Select-Object Name, Path, Description, Caption, 
		@{n='Type';e={
			switch ($_.Type) {
				0          { "Disk Drive" }
				1          { "Print Queue" }
				2          { "Device" }
				2147483648 { "Disk Drive Admin" }
				2147483649 { "Print Queue Admin" }
				2147483650 { "Device Admin" }
				2147483651 { "IPC Admin" }
			}
		}},
		MaximumAllowed, AllowMaximum, Status, InstallDate,
		@{n='Access';e={ $Access }}
		
		updateLogFile $logFileName ($shareDescription)
		updateLogFile $logFileName ("")

		If ($_.Path) {
			# NTFS ACL
			updateLogFile $logFileName ("NTFS ACL")
			updateLogFile $logFileName ("--------")                                 
			
			icacls $_.Path >> $file
			
			ForEach ($system in Get-Content $file)
			{
				updateLogFile $logFileName ($system)
			}
			
			updateLogFile $logFileName ("")

			# Share ACL
			updateLogFile $logFileName ("Share ACL")
			updateLogFile $logFileName ("---------")

			Try { 
				Get-SharePermission $Computer $_.Name >> $file
				
				ForEach ($system in Get-Content $file)
				{
					updateLogFile $logFileName ($system)
				}  
			}
			Catch{
				updateLogFile $logFileName ("Default share: no ACL")
			}
		}
		
		updateLogFile $logFileName ("")
	}
	
	Remove-item $global:tempFileName 2>&1> $null
}

Function Get-ScheduledTasks 
{
	Begin
	{
		$tasks = @()
		$schedule = New-Object -ComObject "Schedule.Service"
	}
	Process
	{
		Function Get-Tasks
		{
			Param($path)
			$out = @()
			$schedule.GetFolder($path).GetTasks(0) | % {
				$xml = [xml]$_.xml
				$out += New-Object psobject -Property @{
					"ComputerName" = $Computer
					"Name" = $_.Name
					"Path" = $_.Path
					"LastRunTime" = $_.LastRunTime
					"NextRunTime" = $_.NextRunTime
					"Actions" = ($xml.Task.Actions.Exec | % { "$($_.Command) $($_.Arguments)" }) -join "`n"
					"Command" = ($xml.Task.Actions.Exec | % { "$($_.Command)" })
					"Triggers" = $(If($xml.task.triggers){ForEach($task in ($xml.task.triggers | gm | Where{$_.membertype -eq "Property"})){$xml.task.triggers.$($task.name)}})
					"Enabled" = $xml.task.settings.enabled
					"Author" = $xml.task.principals.Principal.UserID
					"Description" = $xml.task.registrationInfo.Description
					"LastTaskResult" = $_.LastTaskResult
					"RunAs" = $xml.task.principals.principal.userid
				}
			}
			If(!$RootOnly)
			{
				$schedule.GetFolder($path).GetFolders(0) | % {
					$out += get-Tasks($_.Path)
				}
			}
			$out
		}
		ForEach($Computer in $Name)
		{
			$schedule.connect($env:COMPUTERNAME)
			$tasks += Get-Tasks "\"
		}
	}
	End
	{
		[System.Runtime.Interopservices.Marshal]::ReleaseComObject($schedule) | Out-Null
		Remove-Variable schedule
		
		return $tasks
	}
}

# Tests WMI connection
Try {
	$wmiobject = Get-WMIObject Win32_OperatingSystem -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue
	If (!$?) {
		Throw "[Error] Cannot connect to WMI"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
	Break
}

# Creates log file on current directory
New-Item $logFileName -Type File -Force 2>&1> $null

# Exports secpol to current directory
secedit /export /cfg $global:secpolExportFileName 2>&1> $null

#########
# Tests #
#########

#
#TODO 1 - Authentication
#		> List of local users
#		> List of local groups
#		> Last change date for local administrator password
#		> Password policy
#		> Account lockout policy
#		> Other authentication parameters
#

Write-Host "[1] - Authentication"



# List of local users 

updateLogFile $authentificationFileName ("--=== List of local users ===--")

Try { 
	$colItems = Get-WMIObject Win32_UserAccount -NameSpace "root\CIMV2" -Filter "LocalAccount='$True'" -ErrorAction SilentlyContinue 
	
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $authentificationFileName ("Caption: " + $objItem.Caption)
			updateLogFile $authentificationFileName ("Domain: " + $objItem.Domain)
			updateLogFile $authentificationFileName ("Name: " + $objItem.Name)
			updateLogFile $authentificationFileName ("FullName: " + $objItem.FullName)
			updateLogFile $authentificationFileName ("Description: " + $objItem.Description)
			updateLogFile $authentificationFileName ("Disabled: " + $objItem.Disabled)
			updateLogFile $authentificationFileName ("PasswordChangeable: " + $objItem.PasswordChangeable)
			updateLogFile $authentificationFileName ("PasswordExpires: " + $objItem.PasswordExpires)
			updateLogFile $authentificationFileName ("PasswordRequired: " + $objItem.PasswordRequired)
			updateLogFile $authentificationFileName ("LocalAccount: " + $objItem.LocalAccount)
			updateLogFile $authentificationFileName ("Lockout: " + $objItem.Lockout)
			updateLogFile $authentificationFileName ("SID: " + $objItem.SID)
			updateLogFile $authentificationFileName ("Status: " + $objItem.Status)
			updateLogFile $authentificationFileName ""
		}
		
		Write-Host "[-] List of local users: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve local users"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# List of local groups

updateLogFile $authentificationFileName ("--=== List of local groups ===--")

Try { 
	$colItems = Get-WMIObject Win32_Group -NameSpace "root\CIMV2" -Filter "LocalAccount='$True'" -ErrorAction SilentlyContinue 
	
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $authentificationFileName ("Caption: " + $objItem.Caption)
			updateLogFile $authentificationFileName ("Domain: " + $objItem.Domain)
			updateLogFile $authentificationFileName ("Name: " + $objItem.Name)
			updateLogFile $authentificationFileName ("FullName: " + $objItem.FullName)
			updateLogFile $authentificationFileName ("Description: " + $objItem.Description)
			updateLogFile $authentificationFileName ("LocalAccount: " + $objItem.LocalAccount)
			updateLogFile $authentificationFileName ("SID: " + $objItem.SID)
			updateLogFile $authentificationFileName ("Status: " + $objItem.Status)
			$temp = net localgroup $objItem.Name
			updateLogFile $authentificationFileName $temp
			updateLogFile $authentificationFileName ""
		}
		
		Write-Host "[-] List of local groups: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve local groups"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Last change date for local administrator password

updateLogFile $authentificationFileName ("--=== Last change date for local administrator password ===--")


Try { 
	$colItems = Get-WMIObject Win32_ComputerSystem -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
	
	If ($?) {
		Foreach ($objItem in $colItems) {
			$userName = $objItem.Name				
		}         
		$localAdmin = Get-SWLocalAdmin($userName)
		
		updateLogFile $authentificationFileName ("Last change date for local administrator password: " + $localAdmin.LastPasswordSet)
		
		Write-Host "[-] Last change date for local administrator password: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve last change date for local administrator password"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Password policy

updateLogFile $authentificationFileName ("--=== Password policy ===--")

Try { 
	cmd /C "echo | set /p=A password history must be enabled (PasswordHistorySize): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""PasswordHistorySize""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i)) & echo .)) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=A maximum password age must be configured (MaximumPasswordAge): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""MaximumPasswordAge""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=A minimum password age must be configured (MinimumPasswordAge): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""MinimumPasswordAge""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Password complexity must be enabled (PasswordComplexity): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""PasswordComplexity""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=A minimum password length must be configured (MinimumPasswordLength): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""MinimumPasswordLength""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"
		
	If ($?) {
		Write-Host "[-] Password policy: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve one of password policy parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Account lockout policy

updateLogFile $authentificationFileName ("--=== Account lockout policy ===--")

Try { 
	cmd /C "echo | set /p=A lockout duration must be configured (LockoutDuration): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LockoutDuration""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=A reset lockout count must be configured (ResetLockoutCount): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ResetLockoutCount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=A lockout bad count must be configured (LockoutBadCount): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LockoutBadCount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Account lockout policy: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve one of account lockout policy parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Other authentication parameters

updateLogFile $authentificationFileName ("--=== Default account configuration ===--")

Try { 
	cmd /C "echo | set /p=Default Administrator account must be renamed (NewAdministratorName): >> $global:authentificationFileName"
	cmd /c "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""NewAdministratorName""') do (for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Default Administrator account must be disabled (EnableAdminAccount): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EnableAdminAccount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Default Guest account must be renamed (NewGuestName): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""NewGuestName""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Default Guest account must be disabled (EnableGuestAccount): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EnableGuestAccount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Do not cache previous logons for offline logons"" must be configured (CachedLogonsCount): >> $global:authentificationFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""CachedLogonsCount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:authentificationFileName 2>> $global:logErrorFileName"
		
	If ($?) {
		Write-Host "[-] Other authentication parameters: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve one of other authentication parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

#
#TODO 2 - Network access controls
#		> Network interfaces
#		> Firewall rules
#		> Firewall profiles
#		> Firewall profiles parameters
#		> IPSec parameters
#		> IPSec rules
#		> Network shares
#		> Other network access control parameters
#		> Internet Explorer: To-Do

Write-Host "[2] - Network access controls"


updateLogFile $networkFileName ("===== [2] - Network access controls - Start =====")


# Network interfaces


updateLogFile $networkFileName ("--=== Network interfaces ===--")


Try {
	$colItems = Get-WMIObject Win32_NetworkAdapter -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
	
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $networkFileName ("NetEnabled: " + $objItem.NetEnabled)
			updateLogFile $networkFileName ("ServiceName: " + $objItem.ServiceName)
			updateLogFile $networkFileName ("Index: " + $objItem.Index)
			updateLogFile $networkFileName ("MACAddress: " + $objItem.MACAddress)
			updateLogFile $networkFileName ("AdapterType: " + $objItem.AdapterType)
			updateLogFile $networkFileName ("DeviceID: " + $objItem.DeviceID)
			updateLogFile $networkFileName ("Name: " + $objItem.Name)
			updateLogFile $networkFileName ("NetworkAddresses: " + $objItem.NetworkAddresses)
			updateLogFile $networkFileName ("Speed: " + $objItem.Speed)
			updateLogFile $networkFileName ""
		}
		
		Write-Host "[-] Network interfaces: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve network interfaces"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Firewall rules


updateLogFile $networkFileName ("--=== Firewall rules ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	netsh advfirewall firewall show rule name=all verbose > $file
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $networkFileName ($system)
        }
		
		Write-Host "[-] Firewall rules: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve firewall rules"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Firewall profiles


updateLogFile $networkFileName ("--=== Firewall profiles ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	netsh advfirewall show allprofile >> $file
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $networkFileName ($system)
        }
		
		Write-Host "[-] Firewall profiles: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve firewall profiles"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Firewall profiles parameters


updateLogFile $networkFileName ("--=== Firewall profiles parameters ===--")


Try {
	updateLogFile $networkFileName ("Parameter ""Unidentified networks"" must be configured:")
	cmd /C "echo | set /p=Category: >> $global:networkFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24 /v Category') do (echo | set /p=%a)) & echo .) >> $global:networkFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=CategoryReadOnly: >> $global:networkFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24 /v CategoryReadOnly') do (echo | set /p=%a)) & echo .) >> $global:networkFileName 2>> $global:logErrorFileName"
		
	If ($?) {
		Write-Host "[-] Firewall profiles parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve firewall profiles parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# IPSec parameters


updateLogFile $networkFileName ("--=== IPSec parameters ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	netsh advfirewall show global >> $file
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $networkFileName ($system)
        }
		
		Write-Host "[-] IPSec parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve IPSec parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# IPSec rules


updateLogFile $networkFileName ("--=== IPSec rules ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	netsh advfirewall consec show rule name=all >> $file
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $networkFileName ($system)
        }
		
		Write-Host "[-] IPSec rules: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve IPSec rules"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Network shares


updateLogFile $networkFileName ("--=== Network shares ===--")


Try {
	Get-ShareACL
	
	If ($?) {
		Write-Host "[-] Network shares: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve network shares"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Other network access control parameters


updateLogFile $networkFileName ("--=== Other network access control parameters ===--")


Try { 
	updateLogFile $networkFileName ("The default admin shares must be disabled:")

	cmd /C "echo | set /p=AutoShareServer: >> $global:networkFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\ /v AutoShareServer') do (echo | set /p=%a)) & echo .) >> $global:networkFileName 2>> $global:logErrorFileName"
	
	cmd /C "echo | set /p=AutoShareWks: >> $global:networkFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\ /v AutoShareWks') do (echo | set /p=%a)) & echo .) >> $global:networkFileName 2>> $global:logErrorFileName"
		
	If ($?) {
		Write-Host "[-] Other network access control parameters: OK" -ForegroundColor Green
	}
	Else {
		Throw "[Error] Cannot retrieve one of other network access control parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Internet Explorer

# To-Do		

#
#TODO 3 - System access controls
#		> AppLocker parameters
#		> AppLocker events logs
#		> Other system access controls parameters


Write-Host "[3] - System access controls"

updateLogFile $systemFileName ("===== [3] - System access controls - Start =====")

# AppLocker events logs

updateLogFile $systemFileName ("--=== AppLocker events logs ===--")

Try {
	$file = New-Item $global:tempFileName -Type File -Force
	Get-AppLockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/EXE and DLL" >> $file
	Get-AppLockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/MSI and Script" >> $file
	
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $systemFileName ($system)
        }
		
		Write-Host "[-] Firewall profiles: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve Applocker event logs"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Other system access controls parameters

updateLogFile $systemFileName ("--=== Other system access controls parameters ===--")

Try {
	cmd /C "echo | set /p=The setting ""Enable UAC"" must be configured (EnableLUA): >> $global:systemFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA') do (echo | set /p=%a)) & echo .) >> $global:systemFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Autoplay must be disabled for all drives (NoDriveTypeAutorun): >> $global:systemFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v NoDriveTypeAutorun') do (echo | set /p=%a)) & echo .) >> $global:systemFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Autorun must be disabled for all drives (NoAutorun): >> $global:systemFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ /v NoAutorun') do (echo | set /p=%a)) & echo .) >> $global:systemFileName 2>> $global:logErrorFileName"
		
	If ($?) {
		Write-Host "[-] Other system access controls parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve one of other system access controls parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

#
#TODO 4 - Encryption
#		> Certstore parameters
#		> BitLocker status
#		> TPM status
#		> BitLocker parameters
# 		> TPM backup parameters

Write-Host "[4] - Encryption"

updateLogFile $encryptionFileName ("===== [4] - Encryption - Start =====")

# Certstore parameters

updateLogFile $encryptionFileName ("--=== Certstore parameters ===--")

Try {
	cmd /C "echo | set /p=Parameter ""Turn off automatic updating of trusted root authority certificates"" must be configured (DisableRootAutoUpdate): >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\SystemCertificates\AuthRoot /v DisableRootAutoUpdate') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	
	If ($?) {
		Write-Host "[-] Certstore parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve certstore parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# BitLocker status

updateLogFile $encryptionFileName ("--=== BitLocker status ===--")

Try {
	$file = New-Item $global:tempFileName -Type File -Force
	manage-bde -status >> $file
	
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $encryptionFileName ($system)
        }
		
		Write-Host "[-] BitLocker status: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve BitLocker status"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# TPM status

updateLogFile $encryptionFileName ("--=== TPM status ===--")

Try {
	$file = New-Item $global:tempFileName -Type File -Force
	wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get IsEnabled_InitialValue >> $file
	
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $encryptionFileName ($system)
        }
		
		Write-Host "[-] TPM status: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve TPM status"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# BitLocker parameters

updateLogFile $encryptionFileName ("--=== BitLocker parameters ===--")

Try {
	updateLogFile $encryptionFileName ("Parameter ""Prevent memory overwrite on restart"" must be configured:")
	cmd /C "echo | set /p=MorBehavior: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v MorBehavior') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Provide the unique identifiers for your organization"" must be configured:")
	cmd /C "echo | set /p=IdentificationField: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v IdentificationField') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=IdentificationFieldString: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v IdentificationFieldString') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=SecondaryIdentificationField: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v SecondaryIdentificationField') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure how Bitlocker-protected drives can be recovered (Windows Server 2008 and Vista)"" must be configured:")
	cmd /C "echo | set /p=UseRecoveryPassword: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseRecoveryPassword') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UseRecoveryDrive: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseRecoveryDrive') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Choose default folder for recovery password"" must be configured:")
	cmd /C "echo | set /p=DefaultRecoveryFolderPath: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v DefaultRecoveryFolderPath') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Validate smart card certificate usage rule compliance"" must be configured:")
	cmd /C "echo | set /p=CertificateOID: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v CertificateOID') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Allow access to Bitlocker-protected removable data drives from earlier versions of Windows"" must be configured:")
	cmd /C "echo | set /p=RDVDiscoveryVolumeType: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVDiscoveryVolumeType') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVNoBitLockerToGoReader: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVNoBitLockerToGoReader') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure use of smart cards on removable data drives"" must be configured:")
	cmd /C "echo | set /p=RDVAllowUserCert: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVAllowUserCert') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVEnforceUserCert: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVEnforceUserCert') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure use of passwords on removable data drives"" must be configured:")
	cmd /C "echo | set /p=RDVPassphrase: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVPassphrase') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVEnforcePassphrase: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVEnforcePassphrase') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVPassphraseComplexity: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVPassphraseComplexity') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVPassphraseLength: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVPassphraseLength') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Control use of Bitlocker on removable drives"" must be configured:")
	cmd /C "echo | set /p=RDVConfigureBDE: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVConfigureBDE') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVAllowBDE: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVAllowBDE') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVDisableBDE: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVDisableBDE') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Deny write access to removable drives not protected by Bitlocker"" must be configured:")
	cmd /C "echo | set /p=RDVDenyWriteAccess: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Policies\Microsoft\FVE /v RDVDenyWriteAccess') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVDenyCrossOrg: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVDenyCrossOrg') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Choose how Bitlocker-protected removable drives can be recovered"" must be configured:")
	cmd /C "echo | set /p=RDVRecovery: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVRecovery') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVManageDRA: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVManageDRA') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVRecoveryPassword: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVRecoveryPassword') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVRecoveryKey: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVRecoveryKey') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVHideRecoveryPage: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVHideRecoveryPage') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVActiveDirectoryInfoToStore: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVActiveDirectoryInfoToStore') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RDVRequireActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v RDVRequireActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Allow access to Bitlocker-protected fixed data drives from earlier versions of Windows"" must be configured:")
	cmd /C "echo | set /p=FDVDiscoveryVolumeType: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVDiscoveryVolumeType') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVNoBitLockerToGoReader: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVNoBitLockerToGoReader') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure use of smart cards on fixed data drives"" must be configured:")
	cmd /C "echo | set /p=FDVAllowUserCert: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVAllowUserCert') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVEnforceUserCert: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVEnforceUserCert') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure use of passwords on fixed data drives"" must be configured:")
	cmd /C "echo | set /p=FDVPassphrase: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVPassphrase') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVEnforcePassphrase: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVEnforcePassphrase') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVPassphraseComplexity: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVPassphraseComplexity') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVPassphraseLength: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVPassphraseLength') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Deny write-access to fixed drives not protected by Bitlocker"" must be configured:")
	cmd /C "echo | set /p=FDVDenyWriteAccess: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Policies\Microsoft\FVE /v FDVDenyWriteAccess') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Choose how Bitlocker-protected fixed drives can be recovered"" must be configured:")
	cmd /C "echo | set /p=FDVRecovery: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVRecovery') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVManageDRA: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVManageDRA') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVRecoveryPassword: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVRecoveryPassword') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVRecoveryKey: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVRecoveryKey') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVHideRecoveryPage: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVHideRecoveryPage') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVActiveDirectoryInfoToStore: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVActiveDirectoryInfoToStore') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=FDVRequireActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\FVE /v FDVRequireActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Allow enhanced PINS for startup"" must be configured:")
	cmd /C "echo | set /p=UseEnhancedPin: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UseEnhancedPin') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure minimum PIN length"" must be configured:")
	cmd /C "echo | set /p=MinimumPIN: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v MinimumPIN') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Configure TPM platform validation profile"" must be configured:")
	cmd /C "echo | set /p=Enabled: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v Enabled') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=0: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 0') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=1: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 1') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=2: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 2') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=3: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 3') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=4: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 4') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=5: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 5') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=6: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 6') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=7: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 7') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=8: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 8') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=9: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 9') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=10: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 10') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=11: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 11') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=12: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 12') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=13: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 13') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=14: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 14') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=15: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 15') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=16: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 16') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=17: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 17') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=18: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 18') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=19: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 19') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=20: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 20') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=21: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 21') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=22: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 22') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=23: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE\PlatformValidation /v 23') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Require additional authentication at startup"" must be configured:")
	cmd /C "echo | set /p=UseAdvancedStartup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UseAdvancedStartup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=EnableBDEWithNoTPM: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v EnableBDEWithNoTPM') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UseTPM: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UseTPM') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UseTPMPIN: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UseTPMPIN') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UseTPMKey: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UseTPMKey') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UseTPMKeyPIN: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UseTPMKeyPIN') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Require additional authentication ,Windows Server 2008 and Windows Vista, at startup"" must be configured:")
	cmd /C "echo | set /p=EnableNonTPM: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v EnableNonTPM') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UsePartialEncryptionKey: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UsePartialEncryptionKey') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=UsePIN: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v UsePIN') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	updateLogFile $encryptionFileName ("Parameter ""Choose how Bitlocker-protected operating system drives can be recovered"" must be configured:")
	cmd /C "echo | set /p=OSRecovery: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSRecovery') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSManageDRA: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSManageDRA') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSRecoveryPassword: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSRecoveryPassword') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSRecoveryKey: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSRecoveryKey') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSHideRecoveryPage: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSHideRecoveryPage') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSActiveDirectoryInfoToStore: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSActiveDirectoryInfoToStore') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=OSRequireActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\FVE /v OSRequireActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	
	If ($?) {
		Write-Host "[-] BitLocker parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve BitLocker parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# TPM backup parameters

updateLogFile $encryptionFileName ("--=== TPM backup parameters ===--")

Try {
	updateLogFile $encryptionFileName ("Parameter ""Turn on back up of TPM in Active Directory Domain Services (AD DS)"" must be configured:")
	cmd /C "echo | set /p=ActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\TPM /v ActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RequireActiveDirectoryBackup: >> $global:encryptionFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\TPM /v RequireActiveDirectoryBackup') do (echo | set /p=%a)) & echo .) >> $global:encryptionFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] TPM backup parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve TPM backup parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}


#
#TODO 5 - Logging
#		> Event logs parameters
#		> Standard audit policy
#		> Advanced audit policy

Write-Host "[5] - Logging"

updateLogFile $loggingFileName ("===== [5] - Logging - Start =====")

# Event logs parameters

updateLogFile $loggingFileName ("--=== Event logs parameters ===--")

Try {
	cmd /C " echo| set /p=Path file of the Application Event log file must be configured (File): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v File') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Application Event log size must be configured (MaxSize): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v MaxSize') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Application Event log auto backup must be configured (AutoBackupLogFiles): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v AutoBackupLogFiles') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Application Event log access must be configured (ChannelAccess): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v ChannelAccess') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Application Event log retention must be configured (Retention): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v Retention') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Path file of the Setup Event log file must be configured (File): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup /v File') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Setup Event log size must be configured (MaxSize): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup /v MaxSize') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Setup Event log auto backup must be configured (AutoBackupLogFiles): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup /v AutoBackupLogFiles') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Setup Event log access must be configured (ChannelAccess): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup /v ChannelAccess') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Setup Event log retention must be configured (Retention): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup /v Retention') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Path file of the Security Event log file must be configured (File): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v File') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Security Event log size must be configured (MaxSize): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v MaxSize') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Security Event log auto backup must be configured (AutoBackupLogFiles): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v AutoBackupLogFiles') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Security Event log access must be configured (ChannelAccess): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v ChannelAccess') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The Security Event log retention must be configured (Retention): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v Retention') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Path file of the System Event log file must be configured (File): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v File') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The System Event log size must be configured (MaxSize) >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v MaxSize') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The System Event log auto backup must be configured (AutoBackupLogFiles): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v AutoBackupLogFiles') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The System Event log access must be configured (ChannelAccess): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v ChannelAccess') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=The System Event log retention must be configured (Retention): >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v Retention') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Event logs parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve one of event logs parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Standard audit policy

updateLogFile $loggingFileName ("--=== Standard audit policy ===--")

Try {
	cmd /C "echo | set /p=""""Audit directory service access"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditDSAccess""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit object access"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditObjectAccess""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit privilege use"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditPrivilegeUse""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit account management"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditAccountManage""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit process tracking"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditProcessTracking""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit logon events"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditLogonEvents""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=  """"Audit account logon events"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditAccountLogon""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit of system events"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditSystemEvents""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=""""Audit policy change"" must be configured:"" >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditPolicyChange""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Standard audit policy: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve standard audit policy"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Advanced audit policy

updateLogFile $loggingFileName ("--=== Advanced audit policy ===--")

Try {
	updateLogFile $loggingFileName ("[Account logon]")
		
	cmd /C " echo| set /p=Advanced audit of ""Account Logon: Audit Credential Validation"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE923F-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Logon: Audit Kerberos Authentication Service"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9242-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Logon: Audit Kerberos Service Ticket Operations"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9240-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Logon: Audit Other Account Logon Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9241-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[Account management]")

	cmd /C " echo| set /p=Advanced audit of ""Account Management: Audit Application Group Management"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9239-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Management: Audit Computer Account Management"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9236-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Management: Audit Distribution Group Management"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9238-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Management: Audit Other Account Management Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE923A-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Management: Audit Security Group Management"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9237-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Account Management: Audit User Account Management "" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9235-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[Detailled tracking]")

	cmd /C " echo| set /p=Advanced audit of ""Detailed Tracking: Audit DPAPI Activity"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE922D-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Detailed Tracking: Audit Process Creation"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE922B-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Detailed Tracking: Audit Process Termination"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE922C-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Detailed Tracking: Audit RPC Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE922E-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[DS access]")

	cmd /C " echo| set /p=Advanced audit of ""DS Access: Audit Detailed Directory Service Replication"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE923E-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""DS Access: Audit Directory Service Access"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE923B-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""DS Access: Audit Directory Service Changes"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE923C-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""DS Access: Audit Directory Service Replication"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE923D-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[Logon/Logoff]")

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit Account Lockout"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9217-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit IPsec Extended Mode"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE921A-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit IPsec Main Mode"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9218-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit IPsec Quick Mode"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9219-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit Logoff"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9216-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit Logon"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9215-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit NPS Server"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9243-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit Other Logon/Logoff Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE921C-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Logon/Logoff: Audit Special Logon"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE921B-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[Object access]")

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Application Generated"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9222-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Certification Services"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9221-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Detailed File Share"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9244-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit File Share"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9224-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit File System"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE921D-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Filtering Platform Connection"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9226-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Filtering Platform Packet Drop"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9225-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Handle Manipulation"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9223-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Kernel Objects"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE921F-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Other Object Access Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9227-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit Registry"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE921E-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Object Access: Audit SAM"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9220-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[Policy change]")

	cmd /C " echo| set /p=Advanced audit of ""Policy Change: Audit Policy Change"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE922F-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Policy Change: Audit Authentication Policy Change"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9230-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Policy Change: Audit Authorization Policy Change"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9231-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Policy Change: Audit Filtering Platform Policy Change"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9233-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Policy Change: Audit MPSSVC Rule-Level Policy Change"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9232-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Policy Change: Audit Other Policy Change Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9234-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[Privilege use]")

	cmd /C " echo| set /p=Advanced audit of ""Privilege Use: Audit Non Sensitive Privilege Use"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9229-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Privilege Use: Audit Other Privilege Use Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE922A-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""Privilege Use: Audit Sensitive Privilege Use"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9228-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	updateLogFile $loggingFileName ("[System]")

	cmd /C " echo| set /p=Advanced audit of ""System: Audit IPsec Driver"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9213-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""System: Audit Other System Events"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9214-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""System: Audit Security State Change"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9210-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""System: Audit Security System Extension"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9211-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Advanced audit of ""System: Audit System Integrity"" must be configured: >> $global:loggingFileName"
	cmd /C "echo off && ((for /f ""tokens=5 skip=1 delims=,"" %a in ('auditpol /get /subcategory:""{0CCE9212-69AE-11D9-BED3-505054503030}"" /r') do (echo | set /p=%a)) & echo .) >> $global:loggingFileName 2>> $global:logErrorFileName"
	
	If ($?) {
		Write-Host "[-] Advanced audit policy: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve advanced audit policy"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

#
#TODO 6 - Updates
#		> Windows updates
#		> Windows updates parameters
#		> Installed softwares

Write-Host "[6] - Updates"

updateLogFile $updatesFileName ("===== [6] - Updates - Start =====")

# Windows updates

updateLogFile $updatesFileName ("--=== Windows updates ===--")

Try {
	$file = New-Item $global:tempFileName -Type File -Force
	Get-HotFix | Format-Table  -ErrorAction SilentlyContinue >> $file
	
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $updatesFileName ($system)
        }
		
		Write-Host "[-] Windows updates status: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve Windows updates"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Windows updates parameters

updateLogFile $updatesFileName ("--=== Windows updates parameters ===--")

Try {
	updateLogFile $updatesFileName ("Parameter ""Do not display ""Install Updates and Shut Down"" in Shut Down Windows dialog"" must be configured:")
	cmd /C "echo | set /p=NoAUShutdownOption: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAUShutdownOption') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Do not adjust default option to ""Install Updates and Shut Down"" in Shut Down Windows dialog"" must be configured:")
	cmd /C "echo | set /p=NoAUAsDefaultShutdownOption: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAUAsDefaultShutdownOption') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Enabling Windows Update Power Management to automatically wake up the computer to install scheduled updates"" must be configured:")
	cmd /C "echo | set /p=AUPowerManagement: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUPowerManagement') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Configure Automatic Updates"" must be configured:")
	cmd /C "echo | set /p=NoAutoUpdate: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=AUOptions: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=ScheduledInstallDay: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v ScheduledInstallDay') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=ScheduledInstallTime: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v ScheduledInstallTime') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Specify intranet Microsoft update service location"" must be configured:")
	cmd /C "echo | set /p=UseWUServer: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=WUServer: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUServer') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=WUStatusServer: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v WUStatusServer') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Automatic Updates detection frequency"" must be configured:")
	cmd /C "echo | set /p=DetectionFrequency: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v DetectionFrequency') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=DetectionFrequencyEnabled: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v DetectionFrequencyEnabled') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Allow non-administrators to receive update notifications"" must be configured:")
	cmd /C "echo | set /p=ElevateNonAdmins: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Turn on Software Notifications"" must be configured:")
	cmd /C "echo | set /p=EnableFeaturedSoftware: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v EnableFeaturedSoftware') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Allow Automatic Updates immediate installation"" must be configured:")
	cmd /C "echo | set /p=AutoInstallMinorUpdates: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Turn on recommended updates via Automatic Updates"" must be configured:")
	cmd /C "echo | set /p=IncludeRecommendedUpdates: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v IncludeRecommendedUpdates') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""No auto-restart with logged on users for scheduled automatic updates installations"" must be configured:")
	cmd /C "echo | set /p=NoAutoRebootWithLoggedOnUsers: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoRebootWithLoggedOnUsers') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Re-prompt for restart with scheduled installations"" must be configured:")
	cmd /C "echo | set /p=RebootRelaunchTimeoutEnabled: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v RebootRelaunchTimeoutEnabled') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RebootRelaunchTimeout: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v RebootRelaunchTimeout') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Delay Restart for scheduled installations"" must be configured:")
	cmd /C "echo | set /p=RebootWarningTimeoutEnabled: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v RebootWarningTimeoutEnabled') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RebootWarningTimeout: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v RebootWarningTimeout') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Reschedule Automatic Updates scheduled installations"" must be configured:")
	cmd /C "echo | set /p=RescheduleWaitTimeEnabled: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v RescheduleWaitTimeEnabled') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=RescheduleWaitTime: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v RescheduleWaitTime') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Enable client-side targeting"" must be configured:")
	cmd /C "echo | set /p=TargetGroupEnabled: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v TargetGroupEnabled') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"
	cmd /C "echo | set /p=TargetGroup: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v TargetGroup') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	updateLogFile $updatesFileName ("Parameter ""Allow signed updates from an intranet Microsoft update service location"" must be configured:")
	cmd /C "echo | set /p=AcceptTrustedPublisherCerts: >> $global:updatesFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v AcceptTrustedPublisherCerts') do (echo | set /p=%a)) & echo .) >> $global:updatesFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Windows updates parameters: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve Windows updates parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Installed softwares

updateLogFile $updatesFileName ("--=== Installed softwares ===--")

Try {
	$file = New-Item $global:tempFileName -Type File -Force
	Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-List >> $file
	
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $updatesFileName ($system)
        }
		
		Write-Host "[-] Windows updates status: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve Windows updates"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}


#
#TODO 7 - Security strategy
#		> User rights assigment
#		> Security options

Write-Host "[7] - Security strategy"

updateLogFile $securitySTFileName ("===== [7] - Security strategy - Start =====")

# User rights assigment


updateLogFile $securitySTFileName ("--=== User rights assigment ===--")


Try {
	cmd /C "echo | set /p=Parameter ""Access this computer from the network"" must be configured (SeNetworkLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeNetworkLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Access Credential Manager as a trusted caller"" must be configured (SeTrustedCredManAccessPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeTrustedCredManAccessPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Act as part of the operating system"" must be configured (SeTcbPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeTcbPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Add workstations to domain"" must be configured (SeMachineAccountPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeMachineAccountPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Adjust memory quotas for a process"" must be configured (SeIncreaseQuotaPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeIncreaseQuotaPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Shut down the system"" must be configured (SeShutdownPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeShutdownPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Increase scheduling priority"" must be configured (SeIncreaseBasePriorityPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeIncreaseBasePriorityPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Increase a process working set"" must be configured (SeIncreaseWorkingSetPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeIncreaseWorkingSetPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Allow log on through remote desktop service"" must be configured (SeRemoteInteractiveLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeRemoteInteractiveLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Change the time zone"" must be configured (SeTimeZonePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeTimeZonePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Load and unload device drivers"" must be configured (SeLoadDriverPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeLoadDriverPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Bypass traverse checking"" must be configured (SeChangeNotifyPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeChangeNotifyPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Create symbolic links"" must be configured (SeCreateSymbolicLinkPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeCreateSymbolicLinkPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Create global objects"" must be configured (SeCreateGlobalPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeCreateGlobalPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Create permanent shared objects"" must be configured (SeCreatePermanentPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeCreatePermanentPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i))) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Create a pagefile"" must be configured (SeCreatePagefilePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeCreatePagefilePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Create a token object"" must be configured (SeCreateTokenPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeCreateTokenPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Debug programs"" must be configured (SeDebugPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeDebugPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Perform volume maintenance tasks"" must be configured (SeManageVolumePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeManageVolumePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Impersonate a client after authentication"" must be configured (SeImpersonatePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeImpersonatePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Force shutdown from a remote system"" must be configured (SeRemoteShutdownPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeRemoteShutdownPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Generate security audits"" must be configured (SeAuditPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeAuditPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Manage auditing and security log"" must be configured (SeSecurityPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeSecurityPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Deny logon through network"" must be configured (SeDenyNetworkLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeDenyNetworkLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Deny logon locally"" must be configured (SeDenyInteractiveLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeDenyInteractiveLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Deny logon as a service"" must be configured (SeDenyServiceLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeDenyServiceLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Deny logon as a batch job"" must be configured (SeDenyBatchLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeDenyBatchLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Deny log on through Remote Desktop Services"" must be configured (SeDenyRemoteInteractiveLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeDenyRemoteInteractiveLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Change the system time"" must be configured (SeSystemtimePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeSystemtimePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Modify firmware environment values"" must be configured (SeSystemEnvironmentPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeSystemEnvironmentPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Modify an object label"" must be configured (SeRelabelPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeRelabelPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Logon as a service"" must be configured (SeServiceLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeServiceLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Logon as a batch job"" must be configured (SeBatchLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeBatchLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Profile system performance"" must be configured (SeSystemProfilePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeSystemProfilePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Enable computer and user accounts trusted for delegation"" must be configured (SeEnableDelegationPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeEnableDelegationPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Allow log on locally"" must be configured (SeInteractiveLogonRight): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeInteractiveLogonRight""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Take ownership of files or other objects"" must be configured (SeTakeOwnershipPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeTakeOwnershipPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Profile single process"" must be configured (SeProfileSingleProcessPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeProfileSingleProcessPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Replace a process level token"" must be configured (SeAssignPrimaryTokenPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeAssignPrimaryTokenPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Restore files and directories"" must be configured (SeRestorePrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeRestorePrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Remove computer from docking station"" must be configured (SeUndockPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeUndockPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Back up files and directories"" must be configured (SeBackupPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeBackupPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Synchronize directory service data"" must be configured (SeSyncAgentPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeSyncAgentPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Lock pages in memory"" must be configured (SeLockMemoryPrivilege): >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SeLockMemoryPrivilege""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] User rights assigment: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve user rights assigment"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Security options

updateLogFile $securitySTFileName ("--=== Security options ===--")

Try {
	cmd /C "echo | set /p=Parameter ""Network access: Remotely accessible sub paths and registry paths"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AllowedPaths\Machine""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Let Everyone permissions apply to anonymous users"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EveryoneIncludesAnonymous""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Named Pipes that can be accessed anonymously"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""NullSessionPipes""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Remotely accessible registry path"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AllowedExactPaths\Machine""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Shares that can be accessed anonymously"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""NullSessionShares""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Sharing and security model for local accounts"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ForceGuest""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Do not allow anonymous enumeration of SAM accounts and shares"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RestrictAnonymousSAM""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Do not allow anonymous enumeration of SAM accounts"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RestrictAnonymous""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Allow anonymous SID/Name translation"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LSAAnonymousNameLookup""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Restrict anonymous access to Named Pipes and Shares"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RestrictNullSessAccess""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network access: Do not allow storage of credentials or .NET Passports for network authentication"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""DisableDomainCreds""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Shutdown: Clear virtual memory pagefile on shutdown"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ClearPageFileAtShutdown""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Shutdown: Allow system to be shut down without having to log on"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ShutdownWithoutLogon""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Audit: Shut down system immediately if unable to log Security audits"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""CrashOnAuditFail""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Audit: Audit the access of global system objects"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditBaseObjects""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Audit: Audit the use of backup and restore privilege"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""FullPrivilegeAuditing""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Audit: Force audit policy subcategory settings ,Windows Vista or later, to override audit policy category settings"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SCENoApplyLegacyAuditPolicy""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""FIPSAlgorithmPolicy\Enabled""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network client: Digitally sign communications ,if server agrees"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LanManServer\Parameters\EnableSecuritySignature""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network client: Digitally sign communications ,always"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LanManServer\Parameters\RequireSecuritySignature""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network client: Send unencrypted password to third-party SMB servers"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EnablePlainTextPassword""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Accounts: Limit local account use of blank passwords to console logon only"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LimitBlankPasswordUse""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Accounts: Administrator account status"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EnableAdminAccount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Accounts: Guest account status"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EnableGuestAccount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Display user information when the session is locked"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""DontDisplayLockedUserId""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Recovery console: Allow automatic administrative logon"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RecoveryConsole\SecurityLevel""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Recovery console: Allow floppy copy and access to all drives and all folders"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RecoveryConsole\SetCommand""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Admin Approval Mode for the built-in Administrator account"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Switch to the secure desktop when prompting for elevation"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v PromptOnSecureDesktop') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"
	 
	cmd /C "echo | set /p=The setting ""Allow UIAccess applications to prompt for elevation without using the secure desktop"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableUIADesktopToggle') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Behavior of the elevation prompt for administrators in Admin Approval Mode"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Behavior of the elevation prompt for standard users"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorUser') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Detect application installations and prompt for elevation"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableInstallerDetection') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Only elevate UIAccess applications that are installed in secure locations"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableSecureUIAPaths') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Only elevate executables that are signed and validated"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ValidateAdminCodeSignatures') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Run all administrators in Admin Approval Mode"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The setting ""Virtualize file and registry write failures to per-user locations"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableVirtualization') do (echo | set /p=%a)) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain controller: LDAP server signing requirements"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LDAPServerIntegrity""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain controller: Allow server operators to schedule tasks"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SubmitControl""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain controller: Refuse machine account password changes"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RefusePasswordChange""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""System cryptography: Force strong key protection for user keys stored on the computer"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""Cryptography\ForceKeyProtection""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""DCOM: Machine access restrictions in security descriptor definition language ,SDLL, syntax"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""MachineAccessRestriction""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""DCOM: Machine launch restrictions in security descriptor definition language ,SDLL, syntax"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""MachineLaunchRestriction""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain member: Encrypt secure channel data ,when possible"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SealSecureChannel""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain member: Encrypt or sign secure channel data ,always"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RequireSignOrSeal""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain member: Disable machine account password changes"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""DisablePasswordChange""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain member: Require strong ,Windows 2000 or later, session key"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RequireStrongKey""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Domain member: Digitally sign secure channel data"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SignSecureChannel""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""System objects: Require case insensitivity for non-Windows subsystems"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ObCaseInsensitive""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""System objects: Strengthen default permissions of internal system objects ,e.g. Symbolic Links"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""Session Manager\ProtectionMode""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Require smart card"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ScForceOption""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Smart card removal behavior"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ScRemoveOption""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Message text for users attempting to log on"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LegalNoticeText""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Do not display last user name"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""DontDisplayLastUserName""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Do not require CTRL+ALT+DEL"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""DisableCAD""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Require Domain Controller authentication to unlock workstation"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ForceUnlockLogon""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Prompt user to change password before expiration"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""PasswordExpiryWarning""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Message title for users attempting to log on"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LegalNoticeCaption""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Interactive logon: Number of previous logons to cache ,in case domain controller is not available"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""CachedLogonsCount""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""System settings: Optional subsystems"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""optional""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""System settings: Use certificate rules on Windows Executables for Software restriction policies"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuthenticodeEnabled""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Devices:Restrict CD-ROM access to locally logged-on user only"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AllocateCDRoms""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Devices: Allow undock without having to log on"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""UndockWithoutLogon""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Devices: Prevent users from installing printer drivers"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AddPrinterDrivers""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Devices: Restrict floppy access to locally logged-on user only"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AllocateFloppies""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Devices: Allowed to format and eject removable media"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AllocateDASD""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: LDAP client signing requirements"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LDAPClientIntegrity""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Force logoff when logon hours expire"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ForceLogoffWhenHourExpire""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Do not store LAN Manager hash value on next password change"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""Control\Lsa\NoLMHash""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: LAN Manager authentication level"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LmCompatibilityLevel""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Minimum session security for NTLM SSP based clients"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""NTLMMinClientSec""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network Security: Minimum session security for NTLM SSP based servers"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""NTLMMinServerSec""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Allow LocalSystem NULL session fallback"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""allownullsessionfallback""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Allow PKU2U authentication requests to this computer to use online identities"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AllowOnlineID""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Allow Local System to use computer identity for NTLM"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""UseMachineId""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Configure encryption types allowed for Kerberos"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SupportedEncryptionTypes""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: Add server exceptions in this domain"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""DCAllowedNTLMServers""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""ClientAllowedNTLMServers""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: Audit NTLM authentication in this domain"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditNTLMInDomain""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: Audit Incoming NTLM Traffic"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AuditReceivingNTLMTraffic""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: NTLM authentication in this domain"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RestrictNTLMInDomain""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: Incoming NTLM Traffic"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RestrictReceivingNTLMTraffic""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""RestrictSendingNTLMTraffic""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network server: Digitally sign communications ,if server agrees"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LanmanWorkstation\Parameters\EnableSecuritySignature""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network server: Digitally sign communications ,always"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""LanmanWorkstation\Parameters\RequireSecuritySignature""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network server: Disconnect clients when logon hours expire"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""EnableForcedLogOff""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network server: Amount of idle time required before suspending session"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""AutoDisconnect""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) )) & echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Parameter ""Microsoft network server: Server SPN target name validation level"" must be configured: >> $global:securitySTFileName"
	cmd /C "echo off && ((for /f ""tokens=1,2 delims=="" %a in ('type $global:secpolExportFileName ^| findstr /C:""SmbServerNameHardeningLevel""') do ( for /f ""tokens=*"" %i in ('echo %b') do (echo | set /p=%i) ))& echo .) >> $global:securitySTFileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Security options: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve security options"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}


#
#TODO 8 - Specific points
#		> Scheduled tasks
#		> Startup items
#		> File system
#		> Screensaver
#		> Windows gadgets
#		> WinRM

Write-Host "[8] - Specific points"

updateLogFile $specificPointfileName ("===== [8] - Specific points - Start =====")

# Scheduled tasks


updateLogFile $specificPointfileName ("--=== Scheduled tasks ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	$scheduled_tasks = Get-ScheduledTasks
		
	If ($?) {
		ForEach ($scheduled_task in $scheduled_tasks)
        {
			updateLogFile $specificPointfileName ("Name: " + $scheduled_task.Name)
			updateLogFile $specificPointfileName ("Path: " + $scheduled_task.Path)
			updateLogFile $specificPointfileName ("LastRunTime: " + $scheduled_task.LastRunTime)
			updateLogFile $specificPointfileName ("NextRunTime: " + $scheduled_task.NextRunTime)
			updateLogFile $specificPointfileName ("Actions: " + $scheduled_task.Actions)
			updateLogFile $specificPointfileName ("Triggers: " + $scheduled_task.Triggers)
			updateLogFile $specificPointfileName ("Enabled: " + $scheduled_task.Enabled)
			updateLogFile $specificPointfileName ("Author: " + $scheduled_task.Author)
			updateLogFile $specificPointfileName ("Description: " + $scheduled_task.Description)
			updateLogFile $specificPointfileName ("LastTaskResult: " + $scheduled_task.LastTaskResult)
			updateLogFile $specificPointfileName ("RunAs: " + $scheduled_task.RunAs)
			updateLogFile $specificPointfileName ""
			
			Try {
				$binary_path = $scheduled_task.Command.Replace('"', '')
				cmd /c "icacls ""$binary_path"" > $file" 2>&1> $null
		
				ForEach ($system in Get-Content $file)
				{
					updateLogFile $specificPointfileName ($system)
				}
				
				updateLogFile $specificPointfileName ""
			}
			Catch {}
        }

		Write-Host "[-] Scheduled tasks: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve scheduled tasks"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Startup items


updateLogFile $specificPointfileName ("--=== Startup items ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	$colItems = Get-WMIObject Win32_StartupCommand -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $specificPointfileName ("Command: " + $objItem.Command)
			updateLogFile $specificPointfileName ("User: " + $objItem.User)
			updateLogFile $specificPointfileName ("Caption: " + $objItem.Caption)
			updateLogFile $specificPointfileName ""
			
			$binary_path = $objItem.Command.Split("-")[0].Split("/")[0].Replace('"', '')
			
			Try {
				cmd /c "icacls ""$binary_path"" > $file" 2>&1> $null
		
				ForEach ($system in Get-Content $file)
				{
					updateLogFile $specificPointfileName ($system)
				}
				
				updateLogFile $specificPointfileName ""
			}
			Catch {}
		}

		Write-Host "[-] Startup items: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve startup items"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# File system


updateLogFile $specificPointfileName ("--=== File system ===--")


Try {
	cmd /C " echo| set /p=Parameter ""Hide file name extension"" must be configured (HideFileExt): >> $global:specificPointfileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt') do (echo | set /p=%a)) & echo .) >> $global:specificPointfileName 2>> $global:logErrorFileName"
		
	If ($?) {
		Write-Host "[-] File system: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve file system parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Screensaver


updateLogFile $specificPointfileName ("--=== Screensaver ===--")


Try {
	cmd /C " echo| set /p=Screensaver must be enabled (ScreenSaveActive): >> $global:specificPointfileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query ""HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"" /v ScreenSaveActive') do (echo | set /p=%a)) & echo .) >> $global:specificPointfileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=A password must be required to unlock a computer (ScreenSaverIsSecure): >> $global:specificPointfileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query ""HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"" /v ScreenSaverIsSecure') do (echo | set /p=%a)) & echo .) >> $global:specificPointfileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Screen saver time out (ScreenSaveTimeOut): >> $global:specificPointfileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query ""HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"" /v ScreenSaveTimeOut') do (echo | set /p=%a)) & echo .) >> $global:specificPointfileName 2>> $global:logErrorFileName"

	cmd /C " echo| set /p=Load a specific theme (SCRNSAVE.EXE): >> $global:specificPointfileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query ""HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"" /v SCRNSAVE.EXE') do (echo | set /p=%a)) & echo .) >> $global:specificPointfileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Screensaver: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve screensaver parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Windows gadgets


updateLogFile $specificPointfileName ("--=== Windows gadgets ===--")


Try {
	cmd /C " echo| set /p=Parameter ""Disable desktop gadgets"" must be configured (TurnOffSidebar): >> $global:specificPointfileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar /v TurnOffSidebar') do (echo | set /p=%a)) & echo .) >> $global:specificPointfileName 2>> $global:logErrorFileName"

	If ($?) {
		Write-Host "[-] Security options: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve security options"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# WinRM


updateLogFile $specificPointfileName ("--=== WinRM ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	winrm get winrm/config >> $file 2>> $global:logErrorFileName
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $specificPointfileName ($system)
        }

		Write-Host "[-] WinRM: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve WinRM configuration"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}


#
#TODO 9 - System security
#		> DEP
#		> SEHOP
#		> Registry

Write-Host "[9] - System security"

updateLogFile $systemSecurefileName ("===== [9] - System security - Start =====")

# DEP

updateLogFile $systemSecurefileName ("--=== DEP ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	bcdedit >> $file
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $systemSecurefileName ($system)
        }

		Write-Host "[-] DEP: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve DEP configuration"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# SEHOP


updateLogFile $systemSecurefileName ("--=== SEHOP ===--")

Try {
	$file = New-Item $global:tempFileName -Type File -Force
	Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" -ErrorAction SilentlyContinue >> $file
	
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $systemSecurefileName ($system)
        }

		Write-Host "[-] SEHOP: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve SEHOP configuration"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Registry

updateLogFile $systemSecurefileName ("--=== Registry ===--")

Try {
	cmd /C "echo | set /p=IP source routing must be disabled (DisableIPSourceRouting): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v DisableIPSourceRouting') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Dead gateway detection must be disabled (EnableDeadGWDetect): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v EnableDeadGWDetect') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=ICMP redirect must be disabled (EnableICMPRedirect): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v EnableICMPRedirect') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=PMTU must be disabled (EnablePMTUDiscovery): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v EnablePMTUDiscovery') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Keep alive time must be set (KeepAliveTime): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v KeepAliveTime') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Router discovery must be disabled (PerformRouterDiscovery): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v PerformRouterDiscovery') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The functionality protecting from SynFlood attacks must be enabled (SynAttackProtect): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v SynAttackProtect') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The number of connections authorized in the SYN-RCVD state before protection must be configured (TcpMaxHalfOpen ): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v TcpMaxHalfOpen') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=The number of connections authorized in the SYN-RCVD state for which at least one SYN retransmission has occured must be configured (TcpMaxHalfOpenRetried): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\ /v TcpMaxHalfOpenRetried') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=NoDefaultExempt for IPSec Filtering must be disabled (NoDefaultExempt): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\IPSEC\ /v NoDefaultExempt') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=ResetBrowser trames must be ignored (RefuseReset): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\MrxSmb\Parameters\ /v RefuseReset') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=Server service must be prevented from sending exploration announces (Hidden): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\Lanmanserver\Parameters\ /v Hidden') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"

	cmd /C "echo | set /p=IPv6 protocol must be disabled (DisabledComponents): >> $global:systemSecurefileName"
	cmd /C "echo off && ((for /f ""skip=2 tokens=3"" %a in ('reg query HKLM\System\CurrentControlSet\Services\TCPIP6\Parameters\ /v DisabledComponents') do (echo | set /p=%a)) & echo .) >> $global:systemSecurefileName 2>> $global:logErrorFileName"
	If ($?) {
		Write-Host "[-] Registry: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve one of registry parameters"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}	

#
#TODO 10 - Complementary elements
#		> Computer information
#		> Disks
#		> IP configuration
#		> Routing tables
#		> Listening ports
#		> Running services
#		> Running processes
#		> Export SAM & SYSTEM registry hives

Write-Host "[10] - Complementary elements"

updateLogFile $complementaryElementfileName ("===== [10] - Complementary elements - Start =====")

# Computer information

updateLogFile $complementaryElementfileName ("--=== Computer information ===--")

Try {
	$colItems = Get-WMIObject Win32_ComputerSystem -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $complementaryElementfileName ("Domain: " + $objItem.Domain)
			updateLogFile $complementaryElementfileName ("Manufacturer: " + $objItem.Manufacturer)
			updateLogFile $complementaryElementfileName ("Model: " + $objItem.Model)
			updateLogFile $complementaryElementfileName ("Name: " + $objItem.Name)
			updateLogFile $complementaryElementfileName ("PrimaryOwnerName: " + $objItem.PrimaryOwnerName)
			updateLogFile $complementaryElementfileName ("TotalPhysicalMemory: " + [System.Math]::Round($objItem.TotalPhysicalMemory/1048576) + " Mo")
			updateLogFile $complementaryElementfileName ""
		}
		
		Write-Host "[-] Computer information: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve computer information"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Disks

updateLogFile $complementaryElementfileName ("--=== Disks ===--")

Try {
	$colItems = Get-WMIObject Win32_LogicalDisk -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $complementaryElementfileName ("DeviceID: " + $objItem.DeviceID)
			updateLogFile $complementaryElementfileName ("DriveType: " + $objItem.DriveType)
			updateLogFile $complementaryElementfileName ("FreeSpace: " + $objItem.FreeSpace)
			updateLogFile $complementaryElementfileName ("Size: " + $objItem.Size)
			updateLogFile $complementaryElementfileName ("VolumeName: " + $objItem.VolumeName)
			updateLogFile $complementaryElementfileName ("VolumeSerialNumber: " + $objItem.VolumeSerialNumber)
			updateLogFile $complementaryElementfileName ("FileSystem: " + $objItem.FileSystem)
			updateLogFile $complementaryElementfileName ""
		}
		
		Write-Host "[-] Disks: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve disks information"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# IP configuration


updateLogFile $complementaryElementfileName ("--=== IP configuration ===--")


Try {
	$colItems = Get-WMIObject Win32_NetworkAdapterConfiguration -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $complementaryElementfileName ("IPEnabled: " + $objItem.IPEnabled)
			updateLogFile $complementaryElementfileName ("ServiceName: " + $objItem.ServiceName)
			updateLogFile $complementaryElementfileName ("Description: " + $objItem.Description)
			updateLogFile $complementaryElementfileName ("MACAddress: " + $objItem.MACAddress)
			updateLogFile $complementaryElementfileName ("DHCPEnabled: " + $objItem.DHCPEnabled)
			updateLogFile $complementaryElementfileName ("DHCPServer: " + $objItem.DHCPServer)
			updateLogFile $complementaryElementfileName ("DHCPLeaseExpires: " + $objItem.DHCPLeaseExpires)
			updateLogFile $complementaryElementfileName ("DHCPLeaseObtained: " + $objItem.DHCPLeaseObtained)
			updateLogFile $complementaryElementfileName ("IPAddress: " + $objItem.IPAddress)
			updateLogFile $complementaryElementfileName ("IPSubnet: " + $objItem.IPSubnet)
			updateLogFile $complementaryElementfileName ("Gateway: " + $objItem.DefaultIPGateway)
			updateLogFile $complementaryElementfileName ("DNSDomain: " + $objItem.DNSDomain)
			updateLogFile $complementaryElementfileName ("WINSPrimaryServer: " + $objItem.WINSPrimaryServer)
			updateLogFile $complementaryElementfileName ("DNSDomainSuffixSearchOrder: " + $objItem.DNSDomainSuffixSearchOrder)
			updateLogFile $complementaryElementfileName ("IPFilterSecurityEnabled: " + $objItem.IPFilterSecurityEnabled)
			updateLogFile $complementaryElementfileName ("IPPortSecurityEnabled: " + $objItem.IPPortSecurityEnabled)
			If ($objItem.TcpipNetbiosOptions -eq 0) {
				$TcpipNetbiosOptions = "EnableNetbiosViaDhcp"
			} ElseIf ($objItem.TcpipNetbiosOptions -eq 1) {
				$TcpipNetbiosOptions = "EnableNetbios"
			} ElseIf ($objItem.TcpipNetbiosOptions -eq 2) {
				$TcpipNetbiosOptions = "DisableNetbios"
			}
			updateLogFile $complementaryElementfileName ("TcpipNetbiosOptions: " + $TcpipNetbiosOptions)
			updateLogFile $complementaryElementfileName ""
		}
		
		Write-Host "[-] IP configuration: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve IP configuration"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Routing tables


updateLogFile $complementaryElementfileName ("--=== Routing tables ===--")


Try {
	$colItems = Get-WMIObject Win32_IP4RouteTable -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $complementaryElementfileName ("Age: " + $objItem.Age)
			updateLogFile $complementaryElementfileName ("Description: " + $objItem.Description)
			updateLogFile $complementaryElementfileName ("Destination: " + $objItem.Destination)
			updateLogFile $complementaryElementfileName ("Information: " + $objItem.Information)
			updateLogFile $complementaryElementfileName ("InterfaceIndex: " + $objItem.InterfaceIndex)
			updateLogFile $complementaryElementfileName ("Mask: " + $objItem.Mask)
			updateLogFile $complementaryElementfileName ("Metric1: " + $objItem.Metric1)
			updateLogFile $complementaryElementfileName ("Metric2: " + $objItem.Metric2)
			updateLogFile $complementaryElementfileName ("Metric3: " + $objItem.Metric3)
			updateLogFile $complementaryElementfileName ("Metric4: " + $objItem.Metric4)
			updateLogFile $complementaryElementfileName ("Metric5: " + $objItem.Metric5)
			updateLogFile $complementaryElementfileName ("Name: " + $objItem.Name)
			updateLogFile $complementaryElementfileName ("NextHop: " + $objItem.NextHop)
			updateLogFile $complementaryElementfileName ("Protocol: " + $objItem.Protocol)
			updateLogFile $complementaryElementfileName ("Type: " + $objItem.Type)
			updateLogFile $complementaryElementfileName ""
		}
		
		Write-Host "[-] Routing tables: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve routing tables"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Listening ports


updateLogFile $complementaryElementfileName ("--=== Listening ports ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	netstat -abon >> $file
		
	If ($?) {
		ForEach ($system in Get-Content $file)
        {
            updateLogFile $complementaryElementfileName ($system)
        }
		
		Write-Host "[-] Listening ports: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve listening ports"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Running services


updateLogFile $complementaryElementfileName ("--=== Running services ===--")


Try {
	$file = New-Item $global:tempFileName -Type File -Force
	$colItems = Get-WMIObject Win32_Service -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $complementaryElementfileName ("Name: " + $objItem.Name)
			updateLogFile $complementaryElementfileName ("Caption: " + $objItem.Caption)
			updateLogFile $complementaryElementfileName ("DisplayName: " + $objItem.DisplayName)
			updateLogFile $complementaryElementfileName ("Description: " + $objItem.Description)
			updateLogFile $complementaryElementfileName ("DesktopInteract: " + $objItem.DesktopInteract)
			updateLogFile $complementaryElementfileName ("PathName: " + $objItem.PathName)
			updateLogFile $complementaryElementfileName ("ProcessId: " + $objItem.ProcessId)
			updateLogFile $complementaryElementfileName ("ServiceType: " + $objItem.ServiceType)
			updateLogFile $complementaryElementfileName ("Started: " + $objItem.Started)
			updateLogFile $complementaryElementfileName ("StartMode: " + $objItem.StartMode)
			updateLogFile $complementaryElementfileName ("StartName: " + $objItem.StartName)
			updateLogFile $complementaryElementfileName ("AcceptPause: " + $objItem.AcceptPause)
			updateLogFile $complementaryElementfileName ("AcceptStop: " + $objItem.AcceptStop)
			updateLogFile $complementaryElementfileName ("State: " + $objItem.State)
			updateLogFile $complementaryElementfileName ("Status: " + $objItem.Status)
			updateLogFile $complementaryElementfileName ""
			
			$binary_path = $objItem.Command.Split("-")[0].Split("/")[0]
			
			Try {
				cmd /c "icacls $binary_path > $file" 2>&1> $null
		
				ForEach ($system in Get-Content $file)
				{
					updateLogFile $complementaryElementfileName ($system)
				}
				
				updateLogFile $complementaryElementfileName ""
			}
			Catch {}
		}
		
		Write-Host "[-] Running services: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve running services"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}
Finally {
	Remove-item $global:tempFileName 2>&1> $null
}

# Running processes


updateLogFile $complementaryElementfileName ("--=== Running processes ===--")


Try {
	$colItems = Get-WMIObject Win32_Process -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue 
		
	If ($?) {
		Foreach ($objItem in $colItems) {
			updateLogFile $complementaryElementfileName ("Name: " + $objItem.Name)
			updateLogFile $complementaryElementfileName ("Caption: " + $objItem.Caption)
			updateLogFile $complementaryElementfileName ("Description: " + $objItem.Description)
			updateLogFile $complementaryElementfileName ("CommandLine: " + $objItem.CommandLine)
			If ($objItem.CreationDate -eq $Null) {
				$creationDate = ""
			}
			Else {
				$creationDate = $objItem.ConvertToDateTime($objItem.CreationDate)
			}
			updateLogFile $complementaryElementfileName ("CreationDate: " + $creationDate)
			updateLogFile $complementaryElementfileName ("ExecutablePath: " + $objItem.ExecutablePath)
			updateLogFile $complementaryElementfileName ("ProcessId: " + $objItem.ProcessId)
			updateLogFile $complementaryElementfileName ("PrivatePageCount: " + [System.Math]::Round($objItem.PrivatePageCount/1024) + " Mo")
			Try {
				updateLogFile $complementaryElementfileName ("Owner: " + $objItem.GetOwner().Domain + "\" + $objItem.GetOwner().User)
			}
			Catch {}
			updateLogFile $complementaryElementfileName ""
		}
		
		Write-Host "[-] Running processes: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve running processes"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# GPresult

Try {
	If (Test-Path $global:gpresultFileName) {
		Remove-Item $global:gpresultFileName
	}
	cmd /c "gpresult /H $global:gpresultFileName"
	
	If ($?) {
		Write-Host "[-] GPresult: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve GPresult"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}

# Export SAM & SYSTEM registry hives

Try {
	If (Test-Path $global:SAMhiveFileName) {
		Remove-Item $global:SAMhiveFileName
	}
	If (Test-Path $global:SYSTEMhiveFileName) {
		Remove-Item $global:SYSTEMhiveFileName
	}
	
	cmd /c "reg save HKLM\SAM $global:SAMhiveFileName" 2>&1> $null
	cmd /c "reg save HKLM\SYSTEM $global:SYSTEMhiveFileName" 2>&1> $null
	
	If ($?) {
		Write-Host "[-] Export SAM & SYSTEM registry hives: OK" -ForegroundColor Green
	} Else {
		Throw "[Error] Cannot retrieve SAM & SYSTEM registry hives"
	}
}
Catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
}


# Removes temporary files
If (Test-Path $global:secpolExportFileName) {
	Remove-Item $global:secpolExportFileName
}
If (Test-Path $global:tempFileName) {
	Remove-Item $global:tempFileName
}
updateLogFile $complementaryElementfileName ("--=== EoF ===--")


# Start script python generate file PDF 

Try {
	Start-Process python generatorPDF.py
	Write-Host "[-] Generate file PDF OK" -ForegroundColor Green
}
Catch {
	Write-Host "[-] Fail generate file PDF" -ForegroundColor Red
}