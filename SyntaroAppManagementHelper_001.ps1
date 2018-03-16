<#
.DESCRIPTION
The Module contains a lot of Helpfull Functions to use in Syntaro

.EXAMPLE

    ## Auto Variable Definition, these variables will be defined automatically
    ########################################################
    $PackageName = "Base_Script_Basevision"
    $PackageVersion = "1.0.0"
  


.NOTES
Author: Thomas Kurth/baseVISION
Date:   04.06.2017

History
    001: First Version
    002/2017-07-21/PBE: Changed the Logwriting so that it not always creates new Logfiles. Implemented a Log Rollover. Fixed a Problem with Expand-Zip 
    003/2017-09-19/KUR: Bugfixing Pathresolving for MSI's and Kill Process
    004/2017-11-21/KUR: Remove Font Functions, improved Logging, Error Handling changed in Expand-Zip
    005/2017-12-26/KUR: Added functionality to set file and folder permissions, Easily create Active Setup scripts to set Registry keys.
    006/2018-02-20/KUR: Improving Error Handling in Execute-Exe and Execute-MSI
    007/2018-03-16/KUR: During offline Testing the Packagename and version is not provisioned from Syntaro. If not set it is now dooing a fallback to Offline_SyntaroPkg with version 1.0.0.0
                        Kill-Process supports now Wildcards and also to specify a path. When specifiing a path, all process, where the executable is in this path are killed. 
                        Now we are able to support a FastRetry Action, so instead of killing a process, you can just stop the installation and mark it for a fast retry, then the installation will be retried more often. Stay tuned for a blog post about that.
                        Write-Log Allow the Type "Warning" too instead of only "Warn"
#>
## Manual Variable Definition
########################################################
$DebugPreference = "SilentlyContinue"
$ScriptVersion = "002"
$ScriptName = "AppManagementHelper"

## Auto Variable Definition
########################################################

if($PackageName -eq $null){
    $PackageName = "Offline_SyntaroPkg"
}
if($PackageVersion -eq $null){
    $PackageVersion = "1.0.0.0"
}

$LogPath = "c:\Windows\Logs\_Syntaro"
$LogBaseFileName = "$LogPath\$PackageName`_$PackageVersion"
$MaximumLogSize =0.5 #Maximum Log Size in MB

[string]$MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'
[string]$envProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
[string]$envProgramFilesX86 = ${env:ProgramFiles(x86)}
[string]$envCommonProgramFiles = [Environment]::GetFolderPath('CommonProgramFiles')
[string]$envCommonProgramFilesX86 = ${env:CommonProgramFiles(x86)}

#  Registry keys for native and WOW64 applications
[string[]]$regKeyApplications = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

#  Handle X86 environment variables so they are never empty
If (-not $envCommonProgramFilesX86) { [string]$envCommonProgramFilesX86 = $envCommonProgramFiles }
If (-not $envProgramFilesX86) { [string]$envProgramFilesX86 = $envProgramFiles }

# Try get actual ScriptPath
try{
    try{ 
        $ScriptPathTemp = Split-Path $MyInvocation.MyCommand.Path
    } catch {

    }
    if([String]::IsNullOrWhiteSpace($ScriptPathTemp)){
        $ScriptPathTemp = Split-Path $MyInvocation.InvocationName
    }

    If([String]::IsNullOrWhiteSpace($ScriptPathTemp)){
        $ScriptPath = "c:\Windows"
    } else {
        $ScriptPath = $ScriptPathTemp
    }
} catch {
    $ScriptPath = $FallbackScriptPath
}
 
#region Functions
########################################################

Function Write-Log {
    <#
    .DESCRIPTION
    Write text to a logfile with the current time.

    .PARAMETER Message
    Specifies the message to log.

    .PARAMETER Type
    Type of Message ("Info","Debug","Warn","Error").

    .PARAMETER OutputMode
    Specifies where the log should be written. Possible values are "Console","LogFile" and "Both".

    .PARAMETER Exception
    You can write an exception object to the log file if there was an exception.

    .EXAMPLE
    Write-Log -Message "Start process XY"

    .NOTES
    This function should be used to log information to console or log file.
    #>
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [String]
        $Message
    ,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","Debug","Warn","Warning","Error")]
        [String]
        $Type = "Debug"
    ,
        [Parameter(Mandatory=$false)]
        [Exception]
        $Exception
    )
    
    $DateTimeString = Get-Date -Format "yyyy-MM-dd HH:mm:sszz"
    if($Type -eq "Warning"){
        $Type = "Warn"
    }

    # Add CallStack
    try{
        $CallStack = Get-PSCallStack
        $CallCommands = $CallStack.Command
        [array]::Reverse($CallCommands)
        $CallCommands = $CallCommands -join " -> "
    } catch {

    }
    if($CallCommands){
        $Output = "$DateTimeString `t $Type `t $Message `t $CallCommands"
    } else {
        $Output = ($DateTimeString + "`t" + $Message)
    }

    # Add ExceptionMessage
    if($Exception){
        $ExceptionString =  ("[" + $Exception.GetType().FullName + "] " + $Exception.Message)
        $Output = "$Output `n`t`t $ExceptionString"
    }

    if($Type -eq "Error"){
        Write-Error $output -ErrorAction Continue
        
    } elseif($Type -eq "Warn"){
        Write-Warning $output -WarningAction Continue
    } elseif($Type -eq "Debug"){
        Write-Debug $output 
    } else{
        Write-Verbose $output -Verbose
    }
    $output | Out-File -FilePath  "$LogBaseFileName`_PS.log" -Append
}

Function Check-LogFileSize {
    <#
    .DESCRIPTION
    Check if the Logfile exceds a defined Size and if yes rolles id over to a .old.log.

    .PARAMETER Log
    Specifies the the Path to the Log.

    .PARAMETER MaxSize
    MaxSize in MB for the Maximum Log Size

    .EXAMPLE
    Check-LogFileSize -Log "C:\Temp\Super.log" -Size 1

    #>
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [String]
        $Log
    ,
        [Parameter(Mandatory=$true)]
        [String]
        $MaxSize
    )    
    
    #Create the old.log File
    $LogOld = $Log.Insert(($Log.LastIndexOf(".")),".old")
        
	if (Test-Path $Log) {
		#Write-Log "The Log $Log exists"
        $FileSizeInMB= ((Get-ItemProperty -Path $Log).Length)/1MB
        #Write-Log "The Logs Size is $FileSizeInMB MB"
        #Compare the File Size
        If($FileSizeInMB -ge $MaxSize){
            Write-Log "The definde Maximum Size is $MaxSize MB I need to rollover the Log"
            #If the old.log File already exists remove it
            if (Test-Path $LogOld) {
                Write-Log "The Rollover File $LogOld already exists. I will remove it first"
                Remove-Item -path $LogOld -Force
            }
            #Rename the Log
            Rename-Item -Path $Log -NewName $LogOld -Force
            Write-Log "Rolled the Log file over to $LogOld"

        }
        else{
            #Write-Log "The definde Maximum Size is $MaxSize MB no need to rollover"
        }

	} else {
		Write-Log "The Log $Log dosen't exists"
	}
}

Function New-Folder{
    <#
    .DESCRIPTION
    Creates a Folder if it's not existing.

    .PARAMETER Path
    Specifies the path of the new folder.

    .EXAMPLE
    CreateFolder "c:\temp"

    .NOTES
    This function creates a folder if doesn't exist.
    #>
    param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$Path
    )
	# Check if the folder Exists

	if (Test-Path $Path) {
		Write-Log "Folder: $Path Already Exists"
	} else {
		Write-Log "Creating $Path"
        New-Item -Path $Path -type directory | Out-Null
		Write-Log "Created $Path"
	}
}

Function Set-RegValue {
    <#
    .DESCRIPTION
    Set registry value and create parent key if it is not existing.

    .PARAMETER Path
    Registry Path

    .PARAMETER Name
    Name of the Value

    .PARAMETER Value
    Value to set

    .PARAMETER Type
    Type = Binary, DWord, ExpandString, MultiString, String or QWord

    .EXAMPLE
	    Set-RegValue
	
	    Returns 
	        Property >> Return Object of New-ItemProperty
		    isSuccess >> $false/$true
            ErrorMessage >> $null or Error Message
    #>
    param(
        [Parameter(Mandatory=$True)]
        [string]$Path,
        [Parameter(Mandatory=$True)]
        [string]$Name,
        [Parameter(Mandatory=$True)]
        [AllowEmptyString()]
        [string]$Value,
        [Parameter(Mandatory=$True)]
        [ValidateSet("Binary","DWord","ExpandString","MultiString","String","QWord")]
        [string]$Type
    )
    
    try {
       $ErrorActionPreference = 'Stop' # convert all errors to terminating errors
       Write-Log "Try setting Registry Value $Path, $Name, $Type, $Value"
	   if (-not (Test-Path $Path -erroraction silentlycontinue)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            Write-Log "Registry key $Path created"  
        } 
        $rObject = New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop
        Write-Log "Registry Value $Path, $Name, $Type, $Value set"
        [psobject]$RegValue = New-Object -TypeName 'PSObject' -Property @{
		    Property = $rObject
		    isSuccess = $true
            ErrorMessage = $null
	    }
    } catch {
        Write-Log "Registry value not set $Path, $Name, $Value, $Type" -Type Error -Exception $_.Exception
        [psobject]$RegValue = New-Object -TypeName 'PSObject' -Property @{
		    Property = $null
		    isSuccess = $false
            ErrorMessage = $_.Exception
	    }
    }
    return $RegValue
}

Function Expand-Zip {
    <#
    .DESCRIPTION
    Set registry value and create parent key if it is not existing.

    .PARAMETER File
    Registry Path

    .PARAMETER Destination
    Name of the Value

    .EXAMPLE
	Expand-Zip
	
    #>
    param(
        [Parameter(Mandatory=$True)]
        [string]$File,
        [Parameter(Mandatory=$True)]
        [string]$Destination
    )

    try{
        Write-Log "Start Extracting $File to $Destination"
        if(!(Test-Path $File)){
            if(!(Test-Path "$ScriptPath\$File")){
                throw "Zip File '$File' does not exist."
            } else {
                $File = (Get-Item "$ScriptPath\$File").FullName
            }
        } else {
            $File = (Get-Item $File).FullName
        }
        Write-Log "Using FullName $File"
        if(Test-Path -Path $Destination){
            Write-Log "Destination already exists, starting cleanup directory"
            Remove-Item -Path $Destination -Recurse -Force
        }
        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.Filesystem")
        [System.IO.Compression.zipfile]::ExtractToDirectory($File, $Destination)
        Write-Log "Successfully expanded ZIP File"
    } catch {
        Write-Log "Failed to extract ZIP File" -Type Error -Exception $_.Exception
        throw $_.Exception
    }
}

Function Get-PendingReboot {
    <#
    .SYNOPSIS
	Get the pending reboot status on a local computer.
    .DESCRIPTION
	    Check WMI and the registry to determine if the system has a pending reboot operation from any of the following:
	    a) Component Based Servicing (Vista, Windows 2008)
	    b) Windows Update / Auto Update (XP, Windows 2003 / 2008)
	    d) Pending File Rename Operations (XP, Windows 2003 / 2008)
    .EXAMPLE
	    Get-PendingReboot
	
	    Returns custom object with following properties:
	    ComputerName, LastBootUpTime, IsSystemRebootPending, IsCBServicingRebootPending, IsWindowsUpdateRebootPending, IsFileRenameRebootPending, ErrorMsg

    .EXAMPLE
	    (Get-PendingReboot).IsSystemRebootPending
	    Returns boolean value determining whether or not there is a pending reboot operation.


    #>
    param(
        
    )
        ## Determine if a Windows Vista/Server 2008 and above machine has a pending reboot from a Component Based Servicing (CBS) operation
		Try {
			If (([version]$envOSVersion).Major -ge 5) {
				If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction 'Stop') {
					[nullable[boolean]]$IsCBServicingRebootPending = $true
				}
				Else {
					[nullable[boolean]]$IsCBServicingRebootPending = $false
				}
			}
		}
		Catch {
			[nullable[boolean]]$IsCBServicingRebootPending = $null
			Write-Log "Failed to get IsCBServicingRebootPending." -Exception $_.Exception -Type Error
		}
		
		## Determine if there is a pending reboot from a Windows Update
		Try {
			If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction 'Stop') {
				[nullable[boolean]]$IsWindowsUpdateRebootPending = $true
			}
			Else {
				[nullable[boolean]]$IsWindowsUpdateRebootPending = $false
			}
		}
		Catch {
			[nullable[boolean]]$IsWindowsUpdateRebootPending = $null
			Write-Log "Failed to get IsWindowsUpdateRebootPending." -Exception $_.Exception -Type Error
		}
		
 		## Determine if there is a pending reboot from a pending file rename operation
		[boolean]$IsFileRenameRebootPending = $false
		$PendingFileRenameOperations = $null
		If (Test-RegistryValue -Key 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations') {
			#  If PendingFileRenameOperations value exists, set $IsFileRenameRebootPending variable to $true
			[boolean]$IsFileRenameRebootPending = $true
			#  Get the value of PendingFileRenameOperations
			Try {
				[string[]]$PendingFileRenameOperations = Get-ItemProperty -LiteralPath 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'PendingFileRenameOperations' -ErrorAction 'Stop'
			}
			Catch { 
				Write-Log "Failed to get PendingFileRenameOperations." -Exception $_.Exception -Type Error
			}
		}

        ## Determine if there is a pending reboot for the system
		[boolean]$IsSystemRebootPending = $false
		If ($IsCBServicingRebootPending -or $IsWindowsUpdateRebootPending -or $IsSCCMClientRebootPending -or $IsFileRenameRebootPending) {
			[boolean]$IsSystemRebootPending = $true
		}
		
		## Create a custom object containing pending reboot information for the system
		[psobject]$PendingRebootInfo = New-Object -TypeName 'PSObject' -Property @{
			IsSystemRebootPending = $IsSystemRebootPending
			IsCBServicingRebootPending = $IsCBServicingRebootPending
			IsWindowsUpdateRebootPending = $IsWindowsUpdateRebootPending
			IsFileRenameRebootPending = $IsFileRenameRebootPending
		}
		Write-Log "Pending reboot status on the local computer: `n$($PendingRebootInfo | Format-List | Out-String)" -Type Info
	    return $PendingRebootInfo
}

Function Kill-Process {
<#
    .SYNOPSIS
	Will check if a process is Running and then kill it, Wildcards are allowed.
 

    .DESCRIPTION
	    
    .EXAMPLE
	    Kill-Process -Name "winword.exe"

    .EXAMPLE
	    Kill-Process -Name "winword*"

    #>
    param(
        [Parameter(Mandatory=$false,Position=1)]
        [Parameter(ParameterSetName='Name')]
        [String]$Name,
        [Parameter(ParameterSetName='Path')]
        [Parameter(Mandatory=$false)]
        [String]$Path
    )
    Write-Log "Kill Process $Name requested."
    if(-not [String]::IsNullOrWhiteSpace($Name)){
        $processes = Get-Process -Name $Name -ErrorAction SilentlyContinue
    }
    if(-not [String]::IsNullOrWhiteSpace($Path)){
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -match $path }
    }
    if($processes) {
        foreach($process in $processes){
            Write-Log "Process $($process.Name) is running, therefore killing it."
            Stop-Process -Name $Name -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "Process $Name is not running. continue."
    }
}

Function Execute-MSI {
<#
.SYNOPSIS
	Executes msiexec.exe to perform the following actions for MSI & MSP files and MSI product codes: install, uninstall, patch, repair, active setup.
.DESCRIPTION
	Executes msiexec.exe to perform the following actions for MSI & MSP files and MSI product codes: install, uninstall, patch, repair, active setup.
	If the -Action parameter is set to "Install" and the MSI is already installed, the function will exit.
	Sets default switches to be passed to msiexec based on the preferences in the XML configuration file.
	Automatically generates a log file name and creates a verbose log file for all msiexec operations.
	Expects the MSI or MSP file to be located in the "Files" sub directory of the App Deploy Toolkit. Expects transform files to be in the same directory as the MSI file.
.PARAMETER Action
	The action to perform. Options: Install, Uninstall, Patch, Repair, ActiveSetup.
.PARAMETER Path
	The path to the MSI/MSP file or the product code of the installed MSI.
.PARAMETER Transform
	The name of the transform file(s) to be applied to the MSI. The transform file is expected to be in the same directory as the MSI file.
.PARAMETER Patch
	The name of the patch (msp) file(s) to be applied to the MSI for use with the "Install" action. The patch file is expected to be in the same directory as the MSI file.
.PARAMETER Parameters
	Overrides the default parameters specified in the XML configuration file. Install default is: "REBOOT=ReallySuppress /QB!". Uninstall default is: "REBOOT=ReallySuppress /QN".
.PARAMETER SkipMSIAlreadyInstalledCheck
	Skips the check to determine if the MSI is already installed on the system. Default is: $false.
.PARAMETER IncludeUpdatesAndHotfixes
	Include matches against updates and hotfixes in results.
.EXAMPLE
	Execute-MSI -Action 'Install' -Path 'Adobe_FlashPlayer_11.2.202.233_x64_EN.msi'
	Installs an MSI
.EXAMPLE
	Execute-MSI -Action 'Install' -Path 'Adobe_FlashPlayer_11.2.202.233_x64_EN.msi' -Transform 'Adobe_FlashPlayer_11.2.202.233_x64_EN_01.mst' -Parameters '/QN'
	Installs an MSI, applying a transform and overriding the default MSI toolkit parameters
.EXAMPLE
	[psobject]$ExecuteMSIResult = Execute-MSI -Action 'Install' -Path 'Adobe_FlashPlayer_11.2.202.233_x64_EN.msi' -PassThru
	Installs an MSI and stores the result of the execution into a variable by using the -PassThru option
.EXAMPLE
	Execute-MSI -Action 'Uninstall' -Path '{26923b43-4d38-484f-9b9e-de460746276c}'
	Uninstalls an MSI using a product code
.EXAMPLE
	Execute-MSI -Action 'Patch' -Path 'Adobe_Reader_11.0.3_EN.msp'
	Installs an MSP
.NOTES
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateSet('Install','Uninstall','Patch','Repair')]
		[string]$Action = 'Install',
		[Parameter(Mandatory=$true,HelpMessage='Please enter either the path to the MSI/MSP file')]
		[ValidateScript({($_ -match $MSIProductCodeRegExPattern) -or ('.msi','.msp' -contains [IO.Path]::GetExtension($_))})]
		[Alias('FilePath')]
		[string]$Path,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Transform,
		[Parameter(Mandatory=$false)]
		[Alias('Arguments')]
		[ValidateNotNullorEmpty()]
		[string]$Parameters,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Patch,
		[Parameter(Mandatory=$false)]
		[Alias('LogName')]
		[string]$LogBaseFileName=$LogBaseFileName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$WorkingDirectory=$ScriptPath
	)
	
	## Initialize variable indicating whether $Path variable is a Product Code or not
	[boolean]$PathIsProductCode = $false
		
	## If the path matches a product code
	If ($Path -match $MSIProductCodeRegExPattern) {
		#  Set variable indicating that $Path variable is a Product Code
		[boolean]$PathIsProductCode = $true
	}
		
	## Build the MSI Parameters
	Switch ($action) {
		'Install' { 
            $option = '/i'; 
            [string]$msiLogFile = "$LogBaseFileName`_Install"; 
            $msiDefaultParams = "/QN /Quiet /norestart ALLUSERS=1 REBOOT=ReallySuppress " }
		'Uninstall' { 
            $option = '/x'; 
            [string]$msiLogFile = "$LogBaseFileName`_Uninstall"; 
            $msiDefaultParams = "/QN /Quiet /norestart ALLUSERS=1 REBOOT=ReallySuppress " }
		'Patch' { 
            $option = '/update'; 
            [string]$msiLogFile = "$LogBaseFileName`_Patch"; 
            $msiDefaultParams = "/QN /Quiet /norestart ALLUSERS=1 REBOOT=ReallySuppress " }
		'Repair' { 
            $option = '/f'; 
            [string]$msiLogFile = "$LogBaseFileName`_Repair"; 
            $msiDefaultParams = "/QN /Quiet /norestart REBOOT=ReallySuppress " }
	}
		
	## Append ".log" to the MSI logfile path and enclose in quotes
	If ([IO.Path]::GetExtension($msiLogFile) -ne '.log') {
		[string]$msiLogFile = $msiLogFile + '.log'
		[string]$msiLogFile = "`"$msiLogFile`""
	}
	
    #region Resolve Path
 	## If the MSI is in the Files directory, set the full path to the MSI
	If ([System.IO.Path]::IsPathRooted($Path) -and (Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'SilentlyContinue')){
        [string]$msiFile = $Path
    } ElseIf((Test-Path -LiteralPath (Join-Path -Path $WorkingDirectory -ChildPath $path) -PathType 'Leaf' -ErrorAction 'SilentlyContinue')) {
		[string]$msiFile = Join-Path -Path $WorkingDirectory -ChildPath $path
	}
	ElseIf ($PathIsProductCode) {
		[string]$msiFile = $Path
	}
	Else {
		Write-Log "Failed to find MSI file [$path]." -Type Error
	}
		
	## Set the working directory of the MSI
	If ((-not $PathIsProductCode) -and (-not $workingDirectory)) { [string]$workingDirectory = Split-Path -Path $msiFile -Parent }


		
	## Enumerate all transforms specified, qualify the full path if possible and enclose in quotes
	If ($transform) {
		[string[]]$transforms = $transform -split ','
		0..($transforms.Length - 1) | ForEach-Object {
			If (Test-Path -LiteralPath (Join-Path -Path (Split-Path -Path $msiFile -Parent) -ChildPath $transforms[$_]) -PathType 'Leaf') {
				$transforms[$_] = Join-Path -Path (Split-Path -Path $msiFile -Parent) -ChildPath $transforms[$_].Replace('.\','')
			}
			Else {
				$transforms[$_] = $transforms[$_]
			}
		}
		[string]$mstFile = "`"$($transforms -join ';')`""
	}
		
	## Enumerate all patches specified, qualify the full path if possible and enclose in quotes
	If ($patch) {
		[string[]]$patches = $patch -split ','
		0..($patches.Length - 1) | ForEach-Object {
			If (Test-Path -LiteralPath (Join-Path -Path (Split-Path -Path $msiFile -Parent) -ChildPath $patches[$_]) -PathType 'Leaf') {
				$patches[$_] = Join-Path -Path (Split-Path -Path $msiFile -Parent) -ChildPath $patches[$_].Replace('.\','')
			}
			Else {
				$patches[$_] = $patches[$_]
			}
		}
		[string]$mspFile = "`"$($patches -join ';')`""
	}

        ## Enclose the MSI file in quotes to avoid issues with spaces when running msiexec
	[string]$msiFile = "`"$msiFile`""
    #endregion 
    	
		
	## Start building the MsiExec command line starting with the base action and file
	[string]$argsMSI = "$option $msiFile"
	#  Add MST
	If ($transform) { $argsMSI = "$argsMSI TRANSFORMS=$mstFile TRANSFORMSSECURE=1" }
	#  Add MSP
	If ($patch) { $argsMSI = "$argsMSI PATCH=$mspFile" }
	#  Replace default parameters if specified.
	$argsMSI = "$argsMSI $msiDefaultParams" 
	#  Append parameters to default parameters if specified.
	If ($Parameters) { $argsMSI = "$argsMSI $Parameters" }
	$argsMSI = "$argsMSI /l*v $msiLogFile" 

    
    Write-Log "Installing 'msiexec.exe $argsMSI'"
    try{
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $argsMSI -Wait -PassThru
    } catch {
        Write-Log "Error executing msiexec.exe" -Type Error -Exception $_.Exception
        throw $_.Exception
    }
    do {start-sleep -Milliseconds 500}
    until ($process.HasExited)
    $InstallExitCode = $process.ExitCode
    #Search for Exit Code in Success Exit Code List
    $SuccessExitCodes = @(0,1605, 3010)
    if($SuccessExitCodes -contains $InstallExitCode){
        Write-Log "Successfully $action`ed 'msiexec.exe $argsMSI' with Exit Code $InstallExitCode"
        return $InstallExitCode
    } else {
        return $InstallExitCode
	    Write-Log "Failed to $action 'msiexec.exe $argsMSI' with Exit Code $InstallExitCode" -Type Error
        Throw "Failed to $action 'msiexec.exe $argsMSI' with Exit Code $InstallExitCode"
    }
}

Function Execute-Exe {
<#
.SYNOPSIS
	Executes an executable file and waits until the process has finished. Then the result will be validated.

.PARAMETER Path
	The path to the Executable file.
	

#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,HelpMessage='Please enter either the path to the Executable file')]
		[Alias('FilePath')]
		[string]$Path,
		[Parameter(Mandatory=$false)]
		[Alias('Arguments')]
		[ValidateNotNullorEmpty()]
		[string]$Parameters,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[int[]]$SuccessExitCodes = @(0,1605, 3010),
		[Parameter(Mandatory=$false)]
		[Alias('LogName')]
		[string]$LogBaseFileName=$LogBaseFileName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$WorkingDirectory=$ScriptPath
	)
	
    Write-Log "Start Executing $Path with Arguments '$Parameters'" -Type Debug
    try{
        $process = Start-Process -FilePath $Path -WorkingDirectory $WorkingDirectory -ArgumentList $Parameters -Wait -PassThru
    } catch {
        Write-Log "Error executing msiexec.exe" -Type Error -Exception $_.Exception
        throw $_.Exception
    }
    do {start-sleep -Milliseconds 500}
    until ($process.HasExited)
    $InstallExitCode = $process.ExitCode
    Write-Log "Process has exited with exit code: $InstallExitCode"
    #Search for Exit Code in Success Exit Code List
    if($SuccessExitCodes -contains $InstallExitCode){
        Write-Log "Successfully installed '$($process.Name)' with Exit Code $InstallExitCode"
        return $InstallExitCode
    } else {
        return $InstallExitCode
        Write-Log "Failed to Install '$($process.Name)' with Exit Code $InstallExitCode. Exit Code not in SuccessExitCodes($($SuccessExitCodes -join ","))" -Type Error
        Throw "Failed to Install '$($process.Name)' with Exit Code $InstallExitCode"
    }
}

Function Get-InstalledApplication {
<#
.SYNOPSIS
	Retrieves information about installed applications.
.DESCRIPTION
	Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
	Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
.PARAMETER Name
	The name of the application to retrieve information for. Performs a contains match on the application display name by default.
.PARAMETER Exact
	Specifies that the named application must be matched using the exact name.
.PARAMETER WildCard
	Specifies that the named application must be matched using a wildcard search.
.PARAMETER RegEx
	Specifies that the named application must be matched using a regular expression search.
.PARAMETER ProductCode
	The product code of the application to retrieve information for.
.PARAMETER IncludeUpdatesAndHotfixes
	Include matches against updates and hotfixes in results.
.EXAMPLE
	Get-InstalledApplication -Name 'Adobe Flash'
.EXAMPLE
	Get-InstalledApplication -ProductCode '{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.NOTES

#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string[]]$Name,
		[Parameter(Mandatory=$false)]
		[switch]$Exact = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WildCard = $false,
		[Parameter(Mandatory=$false)]
		[switch]$RegEx = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$ProductCode,
		[Parameter(Mandatory=$false)]
		[switch]$IncludeUpdatesAndHotfixes
	)
	
	If ($name) {
		Write-Log "Get information for installed Application Name(s) [$($name -join ', ')]..."
	}
	If ($productCode) {
		Write-Log "Get information for installed Product Code [$ProductCode]..."
	}
		
	## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
	[psobject[]]$regKeyApplication = @()
	ForEach ($regKey in $regKeyApplications) {
		If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue') {
			[psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue'
			ForEach ($UninstallKeyApp in $UninstallKeyApps) {
				Try {
					[psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
					If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
				}
				Catch{
					Write-Log "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]." -Type Warn -Exception $_.Exception
					Continue
				}
			}
		}
	}

		
	## Create a custom object with the desired properties for the installed applications and sanitize property details
	[psobject[]]$installedApplication = @()
	ForEach ($regKeyApp in $regKeyApplication) {
		Try {
			[string]$appDisplayName = ''
			[string]$appDisplayVersion = ''
			[string]$appPublisher = ''
				
			## Bypass any updates or hotfixes
			If (-not $IncludeUpdatesAndHotfixes) {
				If ($regKeyApp.DisplayName -match '(?i)kb\d+') { Continue }
				If ($regKeyApp.DisplayName -match 'Cumulative Update') { Continue }
				If ($regKeyApp.DisplayName -match 'Security Update') { Continue }
				If ($regKeyApp.DisplayName -match 'Hotfix') { Continue }
			}
				
			## Remove any control characters which may interfere with logging and creating file path names from these variables
			$appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''
			$appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
			$appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]',''
				
			## Determine if application is a 64-bit application
			[boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }
				
			If ($ProductCode) {
				## Verify if there is a match with the product code passed to the script
				If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
					Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]."
					$installedApplication += New-Object -TypeName 'PSObject' -Property @{
						UninstallSubkey = $regKeyApp.PSChildName
						ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
						DisplayName = $appDisplayName
						DisplayVersion = $appDisplayVersion
						UninstallString = $regKeyApp.UninstallString
						InstallSource = $regKeyApp.InstallSource
						InstallLocation = $regKeyApp.InstallLocation
						InstallDate = $regKeyApp.InstallDate
						Publisher = $appPublisher
						Is64BitApplication = $Is64BitApp
					}
				}
			}
				
			If ($name) {
				## Verify if there is a match with the application name(s) passed to the script
				ForEach ($application in $Name) {
					$applicationMatched = $false
					If ($exact) {
						#  Check for an exact application name match
						If ($regKeyApp.DisplayName -eq $application) {
							$applicationMatched = $true
							Write-Log "Found installed application [$appDisplayName] version [$appDisplayVersion] using exact name matching for search term [$application]."
						}
					}
					ElseIf ($WildCard) {
						#  Check for wildcard application name match
						If ($regKeyApp.DisplayName -like $application) {
							$applicationMatched = $true
							Write-Log "Found installed application [$appDisplayName] version [$appDisplayVersion] using wildcard matching for search term [$application]."
						}
					}
					ElseIf ($RegEx) {
						#  Check for a regex application name match
						If ($regKeyApp.DisplayName -match $application) {
							$applicationMatched = $true
							Write-Log "Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$application]."
						}
					}
					#  Check for a contains application name match
					ElseIf ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
						$applicationMatched = $true
						Write-Log "Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]."
					}
						
					If ($applicationMatched) {
						$installedApplication += New-Object -TypeName 'PSObject' -Property @{
							UninstallSubkey = $regKeyApp.PSChildName
							ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
							DisplayName = $appDisplayName
							DisplayVersion = $appDisplayVersion
							UninstallString = $regKeyApp.UninstallString
							InstallSource = $regKeyApp.InstallSource
							InstallLocation = $regKeyApp.InstallLocation
							InstallDate = $regKeyApp.InstallDate
							Publisher = $appPublisher
							Is64BitApplication = $Is64BitApp
						}
					}
				}
			}
		}
		Catch {
			Write-Log -Message "Failed to resolve application details from registry for [$appDisplayName]." -Type Error -Exception $_.Exception
			Continue
		}
	}
	Write-Log "Found $($installedApplication.Count) Apps."
	return $installedApplication

}
 
Function New-Shortcut { 
<#   
.SYNOPSIS   
    This script is used to create a  shortcut.         
.DESCRIPTION   
    This script uses a Com Object to create a shortcut. 
.PARAMETER Path 
    The path to the shortcut file.  .lnk will be appended if not specified.  If the folder name doesn't exist, it will be created. 
.PARAMETER TargetPath 
    Full path of the target executable or file. 
.PARAMETER Arguments 
    Arguments for the executable or file. 
.PARAMETER Description 
    Description of the shortcut. 
.PARAMETER HotKey 
    Hotkey combination for the shortcut.  Valid values are SHIFT+F7, ALT+CTRL+9, etc.  An invalid entry will cause the  
    function to fail. 
.PARAMETER WorkDir 
    Working directory of the application.  An invalid directory can be specified, but invoking the application from the  
    shortcut could fail. 
.PARAMETER WindowStyle 
    Windows style of the application, Normal (1), Maximized (3), or Minimized (7).  Invalid entries will result in Normal 
    behavior. 
.PARAMETER Icon 
    Full path of the icon file.  Executables, DLLs, etc with multiple icons need the number of the icon to be specified,  
    otherwise the first icon will be used, i.e.:  c:\windows\system32\shell32.dll,99 
.PARAMETER admin 
    Used to create a shortcut that prompts for admin credentials when invoked, equivalent to specifying runas. 
.NOTES   
    Author        : Rhys Edwards 
    Email        : powershell@nolimit.to   
.INPUTS 
    Strings and Integer 
.OUTPUTS 
    True or False, and a shortcut 
.LINK   
    Script posted over:  N/A   
.EXAMPLE   
    New-Shortcut -Path c:\temp\notepad.lnk -TargetPath c:\windows\notepad.exe     
    Creates a simple shortcut to Notepad at c:\temp\notepad.lnk 
.EXAMPLE 
    New-Shortcut "$($env:Public)\Desktop\Notepad" c:\windows\notepad.exe -WindowStyle 3 -admin 
    Creates a shortcut named Notepad.lnk on the Public desktop to notepad.exe that launches maximized after prompting for  
    admin credentials. 
.EXAMPLE 
    New-Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe -icon "c:\windows\system32\shell32.dll,99" 
    Creates a shortcut named Notepad.lnk on the user's desktop to notepad.exe that has a pointy finger icon (on Windows 7). 
.EXAMPLE 
    New-Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe C:\instructions.txt 
    Creates a shortcut named Notepad.lnk on the user's desktop to notepad.exe that opens C:\instructions.txt  
.EXAMPLE 
    New-Shortcut "$($env:USERPROFILE)\Desktop\ADUC" %SystemRoot%\system32\dsa.msc -admin  
    Creates a shortcut named ADUC.lnk on the user's desktop to Active Directory Users and Computers that launches after  
    prompting for admin credentials 
#> 
 
[CmdletBinding()] 
param( 
    [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=0)]  
    [Alias("File","Shortcut")]  
    [string]$Path, 
 
    [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=1)]  
    [Alias("Target")]  
    [string]$TargetPath, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=2)]  
    [Alias("Args","Argument")]  
    [string]$Arguments, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=3)]   
    [Alias("Desc")] 
    [string]$Description, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=4)]   
    [string]$HotKey, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=5)]   
    [Alias("WorkingDirectory","WorkingDir")] 
    [string]$WorkDir, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=6)]   
    [int]$WindowStyle, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=7)]   
    [string]$Icon, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True)]   
    [switch]$admin 
) 
 
 
Process { 
  Write-Log "Create shortcut($Path) for $TargetPath"
  If (!($Path -match "^.*(\.lnk)$")) { 
    $Path = "$Path`.lnk" 
  } 
  [System.IO.FileInfo]$Path = $Path 
  Try { 
    If (!(Test-Path $Path.DirectoryName)) { 
      md $Path.DirectoryName -ErrorAction Stop | Out-Null 
    } 
  } Catch { 
    Write-Log "Unable to create $($Path.DirectoryName), shortcut cannot be created" -Type Error
    Return $false 
    Break 
  } 
 
 
  # Define Shortcut Properties 
  $WshShell = New-Object -ComObject WScript.Shell 
  $Shortcut = $WshShell.CreateShortcut($Path.FullName) 
  $Shortcut.TargetPath = $TargetPath 
  $Shortcut.Arguments = $Arguments 
  $Shortcut.Description = $Description 
  $Shortcut.HotKey = $HotKey 
  $Shortcut.WorkingDirectory = $WorkDir 
  $Shortcut.WindowStyle = $WindowStyle 
  If ($Icon){ 
    $Shortcut.IconLocation = $Icon 
  } 
 
  Try { 
    # Create Shortcut 
    $Shortcut.Save() 
    # Set Shortcut to Run Elevated 
    If ($admin) {      
      $TempFileName = [IO.Path]::GetRandomFileName() 
      $TempFile = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName) 
      $Writer = New-Object System.IO.FileStream $TempFile, ([System.IO.FileMode]::Create) 
      $Reader = $Path.OpenRead() 
      While ($Reader.Position -lt $Reader.Length) { 
        $Byte = $Reader.ReadByte() 
        If ($Reader.Position -eq 22) {$Byte = 34} 
        $Writer.WriteByte($Byte) 
      } 
      $Reader.Close() 
      $Writer.Close() 
      $Path.Delete() 
      Rename-Item -Path $TempFile -NewName $Path.Name | Out-Null 
    } 
    Return $True 
  } Catch {
Write-Log "Unable to create $($Path.FullName)" -Type Error -Exception $Error[0].Exception
Return $False 
}

}
}

Function Set-Permission {

    <#
    .SYNOPSYS
        Allows to change permissions on files or folders
    .PARAMETER Path
        Path to the folder or file you want to modify (ex: C:\Temp)
    .PARAMETER User
        One or more user names (ex: BUILTIN\Users, DOMAIN\Admin)
    .PARAMETER Permission
        To remove permission use: None'
    .PARAMETER Recurse
        If you use this switch, permissions will be recursive on folder and file children
    .EXAMPLE
        Will grant FullControl permissions to 'John' and 'Users' on 'C:\Temp' and it's files and folders children.
        PS C:\>Set-Permission -Path "C:\Temp" -User "DOMAIN\John", "BUILTIN\Utilisateurs" -Permission FullControl -Recurse
    .EXAMPLE
        Will grant Read permissions to 'John' on 'C:\Temp\pic.png'
        PS C:\>Set-Permission -Path "C:\Temp\pic.png" -User "DOMAIN\John" -Permission Read
    .EXAMPLE
        Will remove all permissions to 'John' on 'C:\Temp\Private'
        PS C:\>Set-Permission -Path "C:\Temp\Private" -User "DOMAIN\John" -Permission None

        Conditions : John need to have explicit existing permissions on the Path or File
    .NOTE
        Thanks to the Author. Modified by Thomas Kurth to Write-Logs according to the needs of Syntaro.
        Author : Julian DA CUNHA - dacunha.julian@gmail.com
    #>

    [CmdletBinding()]
    Param (
        [Parameter( Mandatory=$True, 
                    Position=0,
		    HelpMessage = "Path to the folder or file you want to modify (ex: C:\Temp)" )]
        [ValidateScript({Test-Path $_})]
        [Alias('File', 'Folder')]
        [String] $Path,

        [Parameter( Mandatory=$True, 
                    Position=1,
                    HelpMessage = "One or more user names (ex: BUILTIN\Users, DOMAIN\Admin)" )]
        [Alias('Username', 'Users')]
        [String[]] $User,

        [Parameter( Mandatory=$True,
                    Position=2,
                    HelpMessage = "To remove permission use: None, to see all the possible permissions go to 'http://technet.microsoft.com/fr-fr/library/ff730951.aspx'")]
        [Alias('Acl', 'Grant')]
        [ValidateSet("AppendData", "ChangePermissions", "CreateDirectories", "CreateFiles", "Delete", `
                     "DeleteSubdirectoriesAndFiles", "ExecuteFile", "FullControl", "ListDirectory", "Modify",`
                     "Read", "ReadAndExecute", "ReadAttributes", "ReadData", "ReadExtendedAttributes", "ReadPermissions",`
                     "Synchronize", "TakeOwnership", "Traverse", "Write", "WriteAttributes", "WriteData", "WriteExtendedAttributes", "None")]
        [String] $Permission,

        [Parameter( Mandatory=$False, 
                    HelpMessage = "If you use this switch, permissions will be recursive on folder and file children" )]
        [Switch] $Recurse
    )

    Begin {
        Write-Log "Set permissions $Permission on $Path for $User with Recurse $Recurse"
        # Test run as Administrator
        $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
 	$prp=new-object System.Security.Principal.WindowsPrincipal($wid)
 	$adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 	$IsAdmin=$prp.IsInRole($adm)
        If (!$IsAdmin){
            Write-Log -Message "Insufficient privileges. Try to run it as Administrator." -Type Error
	    throw "Insufficient privileges. Try to run it as Administrator."
        }

        # Set permissions
        If ($Permission -ne "None"){
            $Permission = [System.Security.AccessControl.FileSystemRights]$Permission
        }

        # Enable recursive permissions
        If ($Recurse){
            $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]
            $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]($InheritanceFlag::ContainerInherit -bor $InheritanceFlag::ObjectInherit)
        } Else { 
            $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
        }

        # Set Propagation
        $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None

        # Allow Object access
        $Allow = [System.Security.AccessControl.AccessControlType]::Allow

        # Set permissions for special accounts
        $ObjSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $AdminsSID = $ObjSID.Translate( [System.Security.Principal.NTAccount])
        $AdminsAccountName = $AdminsSID.Value

        $ObjSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $SystemSID = $ObjSID.Translate( [System.Security.Principal.NTAccount])
        $SystemAccountName = $SystemSID.Value
        
        $Admin = New-Object System.Security.Principal.NTAccount($AdminsAccountName)
        $System = New-Object System.Security.Principal.NTAccount($SystemAccountName)
    }

    Process {

        # Get object acls
        $Acl = Get-Acl $Path
        # Disable inherance, Preserve inherited permissions
        $Acl.SetAccessRuleProtection($True, $False)

        # Set Permissions for Administrators and System
        $SpecialPermission = [System.Security.AccessControl.FileSystemRights]::FullControl
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Admin, $SpecialPermission, $InheritanceFlag, $PropagationFlag, $Allow)
        $Acl.AddAccessRule($Rule)
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($System, $SpecialPermission, $InheritanceFlag, $PropagationFlag, $Allow)
        $Acl.AddAccessRule($Rule)
        $null = Set-Acl -Path $Path -AclObject $Acl

        # Apply permissions on Users
        Foreach ($U in $User){

            # Set Username
            $Username = New-Object System.Security.Principal.NTAccount($U)

            # Set or Remove permissions
            If ($Permission -ne "None"){

                $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Username, $Permission, $InheritanceFlag, $PropagationFlag, $Allow)
                $Acl.AddAccessRule($Rule)
                Write-Log "ACL - Add($Username, $Permission, $InheritanceFlag, $PropagationFlag, $Allow)"

            } Else {

                # Check If user is in security descriptor
                $Remove = $Acl.Access | Where { $_.IdentityReference -eq $U }

                If ($Remove){

                    $RemoveRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Remove.IdentityReference, $Remove.FileSystemRights, $Remove.InheritanceFlags, $Remove.PropagationFlags, $Remove.AccessControlType)
                    $Acl.RemoveAccessRuleAll($RemoveRule)
                    Write-Log "ACL - RemoveAll($($Remove.IdentityReference), $($Remove.FileSystemRights), $($Remove.InheritanceFlags), $($Remove.PropagationFlags), $($Remove.AccessControlType))"

                }
            }
        }
    }

    End {
        $null = Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
    }
}

function Set-RegistryValueForAllUsers {
    <#
    .SYNOPSIS
        This function uses Active Setup to create a "seeder" key which creates or modifies a user-based registry value
        for all users on a computer. If the key path doesn't exist to the value, it will automatically create the key and add the value.
    .EXAMPLE
        PS> Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'Setting'; 'Type' = 'String'; 'Value' = 'someval'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
    
        This example would modify the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something' to 'someval'
        for every user registry hive.
    .PARAMETER RegistryInstance
        A hash table containing key names of 'Name' designating the registry value name, 'Type' to designate the type
        of registry value which can be 'String,Binary,Dword,ExpandString or MultiString', 'Value' which is the value itself of the
        registry value and 'Path' designating the parent registry key the registry value is in.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable[]]$RegistryInstance
    )
    try {
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
        
        ## Change the registry values for the currently logged on user. Each logged on user SID is under HKEY_USERS
        $LoggedOnSids = (Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' }).PSChildName
        Write-Log "Found $($LoggedOnSids.Count) logged on user SIDs"
        foreach ($sid in $LoggedOnSids) {
            Write-Log -Message "Loading the user registry hive for the logged on SID $sid"
            foreach ($instance in $RegistryInstance) {
                ## Create the key path if it doesn't exist
                New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null
                ## Create (or modify) the value specified in the param
                Set-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -Type $instance.Type -Force
            }
        }
        
        ## Create the Active Setup registry key so that the reg add cmd will get ran for each user
        ## logging into the machine.
        ## http://www.itninja.com/blog/view/an-active-setup-primer
        Write-Log "Setting Active Setup registry value to apply to all other users"
        foreach ($instance in $RegistryInstance) {
            ## Generate a unique value (usually a GUID) to use for Active Setup
            $Guid = [guid]::NewGuid().Guid
            $ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
            ## Create the GUID registry key under the Active Setup key
            New-Item -Path $ActiveSetupRegParentPath -Name $Guid -Force | Out-Null
            $ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\$Guid"
            Write-Log "Using registry path '$ActiveSetupRegPath'"
            
            ## Convert the registry value type to one that reg.exe can understand.  This will be the
            ## type of value that's created for the value we want to set for all users
            switch ($instance.Type) {
                'String' {
                    $RegValueType = 'REG_SZ'
                }
                'Dword' {
                    $RegValueType = 'REG_DWORD'
                }
                'Binary' {
                    $RegValueType = 'REG_BINARY'
                }
                'ExpandString' {
                    $RegValueType = 'REG_EXPAND_SZ'
                }
                'MultiString' {
                    $RegValueType = 'REG_MULTI_SZ'
                }
                default {
                    throw "Registry type '$($instance.Type)' not recognized"
                }
            }
            
            ## Build the registry value to use for Active Setup which is the command to create the registry value in all user hives
            $ActiveSetupValue = "reg add {0} /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
            Write-Log -Message "Active setup value is '$ActiveSetupValue'"
            ## Create the necessary Active Setup registry values
            Set-ItemProperty -Path $ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'Version' -Value '1' -Force
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'StubPath' -Value $ActiveSetupValue -Force
        }
    } catch {
        Write-Log $_.Exception.Message
    }
}

Function Add-FastRetry {
    <#
    .DESCRIPTION
    Adds trigger to existing scheduled task

    .PARAMETER TaskName
    Specifies when the task should be triggered. Default is Syntaro Installer

    .PARAMETER Delay
    Delay specifies, how many minutes should be waited until the scheduled task should be run
    Minimum of the delay is 30min

    .PARAMETER AppName
    The name of the installed application

    .PARAMETER NumberOfRetry
    Specifies, how many times, the task should be rerun until it is aborted. Default will be 20

    .EXAMPLE
    Add-Trigger -Delay 5

    .NOTES
    This function should be used to add trigers to an existing scheduled task
    #>
    param(
        [Parameter(Mandatory=$false)]
        [String]
        $TaskName = "Syntaro Updater"
    ,
        [Parameter(Mandatory=$true)]
        [ValidateScript({if($_ -ge 30){
                            $true
                            }else{
                            Write-Log "Delay must be at least 30"
                            $false
                            }
                        })]
        [int]
        $Delay
    ,
        [Parameter(Mandatory=$false)]
        [String]
        $AppName = $packageName
    ,
        [Parameter(Mandatory=$false)]
        [int]
        $NumberOfRetry = 20
    )

    

    $regPath = Get-RegistrySyntaroAppPath -AppName $AppName

    
    $ValueData = Get-ItemProperty -Path $regPath -Name 'RetryCount' -ErrorAction SilentlyContinue
    Write-Log "Current Retry number is '$($ValueData.RetryCount)'" -Type Info
    IF($ValueData){
        [int]$retry = $valueData.RetryCount
        #check if defined maximum number of retry was reached
        if($retry -ge  $NumberOfRetry){
            #calling functoin to remove triggers if max number of retry was reached
            Remove-FastRetry -AppName $AppName -TaskName $TaskName -regEntry $false
            Write-Log "Maximum number of retry was reached" -Type Warn
            #exit because max number of retry was reached
            Throw "Specified max retry number was exceeded"
        }else{
            #counting up retry count in the registry
            $retry++
            Write-Log "Retry number $retry"
            Set-RegValue -Path $regPath -Name 'RetryCount' -Type Dword -Value $retry
        }
    }else {
        #create registry value for retry count
        Write-Log "Creating new registy entry for retry count"
        Set-RegValue -Path $regPath -Name 'RetryCount' -Type Dword -Value 1
    }

    #Creatinng new trigger for the scheduled task.
    $newTrigger = @($(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($delay)),$(New-ScheduledTaskTrigger -Daily -At 12AM))

    Try{
        #setting defined triggers for scheduled task
        Set-ScheduledTask -TaskName $TaskName -Trigger $newTrigger -ErrorAction Stop
        Write-Log "Trigger was set to run in $delay minutes" -Type Info
    }catch{
        Write-Log "Could not add a new trigger for scheduled task" -Type Error -Exception $_.Exception
        Throw $_.Exception
    }
    
}

Function Get-RegistrySyntaroAppPath {
        <#
    .DESCRIPTION
    Returns the Registry Path of the Application

    .PARAMETER AppName
    The name of the application for which the registry path should be catched

    .EXAMPLE
    Get-RegistrySyntaroAppPath

    .NOTES
    
    #>
    param(
        [Parameter(Mandatory=$false)]
        [String]
        $AppName = $packageName
    )
    try{
        $regItems = Get-ChildItem -path $RegistrySyntaroBasePath -ErrorAction Stop | Get-ItemProperty -Name 'Name'
    }catch{
        Write-Log "Could not get registry items" -Type Error -Exception $_.Exception
        Trhow $_.Exception
    }
    Write-Log "Checking if registry entry for defined application '$AppName' exists" -Type Info
    foreach($item in $regItems){
        #checking if registry key for defined application exists and setting registry path
        if($item.name -match $AppName){
            $regPath = $item.PSPath
            Write-Log "Found '$regPath' for '$AppName'"
        }
    }
    #check if regPath was set and exit if none is set
    if(!($regPath)){
        Write-Log "Defined application '$AppName' could not be found" -Type Error
        Throw "Could not find registry key for specified application"
    }
    return $regPath
}

Function Remove-FastRetry {
    <#
    .DESCRIPTION
    Removes all trigger which are set to run once to an existing scheduled task

    .PARAMETER TaskName
    Specifies which task should be triggered. Defulat is Syntaro Installer

    .PARAMETER AppName
    The name of the application, which should be installed.

    .EXAMPLE
    Remove-Trigger

    .NOTES
    This function should be used to remove trigers to an existing scheduled task
    #>
    param(
        [Parameter(Mandatory=$false)]
        [String]
        $TaskName = "Syntaro Updater"
    ,
        [Parameter(Mandatory=$false)]
        [String]
        $AppName = $packageName
    ,
        [Parameter(Mandatory=$false)]
        [boolean]
        $regEntry = $true
    )

    if($regEntry){
        $regPath = Get-RegistrySyntaroAppPath -AppName $AppName

        $ValueData = Get-ItemProperty -Path $regPath -Name 'RetryCount' -ErrorAction SilentlyContinue
        Write-Log "Current Retry number is '$($ValueData.RetryCount)'" -Type Info
        IF($ValueData){
            try{
                #Deleting registy key for the retryCount
                Remove-ItemProperty -Path $regPath -Name 'RetryCount' -Force
                Write-Log "Registry value from $regPath was deleted"
            }catch{
                Write-Log "Could not delete RetryCount" -Type Error -Exception $_.Exception
                Throw $_.Exception
            }
        }else {
        Write-Log "Registry value for RetryCount does not exist in $regPath" -Type Warning
        }
    }
    #Creating trigger to run once every day
    $newTrigger = New-ScheduledTaskTrigger -Daily -At 12AM

    Try{
        #Setting defined Trigger for the scheduled task
        Set-ScheduledTask -TaskName $TaskName -Trigger $newTrigger -ErrorAction Stop
        Write-Log "Trigger was set to run daily at 12AM"
    }catch{
        Write-Log "Could not add a new trigger for scheduled task" -Type Error -Exception $_.Exception
        Throw $_.Exception
    }
}
#endregion

#region Initialization
########################################################
    #Check if the Log Folder exists otherwise create it
    if (-! (Test-Path $LogPath)) {
		New-Item -Path $LogPath -type directory | Out-Null
	}
   
    #Check if the Log is to big
    Check-LogFileSize -Log "$LogBaseFileName`_PS.log" -MaxSize $MaximumLogSize

#endregion
