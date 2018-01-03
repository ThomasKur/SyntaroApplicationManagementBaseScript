<#
.DESCRIPTION
The Script contains a Sample to add Firewall Rules on Client, to use in Syntaro
.NOTES
Author: Thomas Kurth/baseVISION
Date:   27.12.2017
History:
    001: First Version
#>
#Configure Firewall
Execute-Exe -Path "c:\Windows\System32\cmd.exe" -Parameters "/c ConfigureFirewall.cmd"
$exist = Get-NetFirewallRule -DisplayName "Java(TM) Platform SE binary" -ErrorAction SilentlyContinue
if($exist){
    Remove-NetFirewallRule -DisplayName "Java(TM) Platform SE binary" 
}
$paths = (Get-Item -Path "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment\*" -ErrorAction SilentlyContinue | Get-ItemProperty -Name JavaHome).JavaHome
$paths += (Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment\*" -ErrorAction SilentlyContinue | Get-ItemProperty -Name JavaHome).JavaHome
 
$paths = $paths | Select-Object -Unique
foreach($path in $paths){
    Write-Log "Add Firewall RUle for '$path\bin\javaw.exe'"
    New-NetFirewallRule -DisplayName "Java(TM) Platform SE binary" -Enabled True -Profile Domain -Direction Inbound -Action Allow -Description "Java(TM) Platform SE binary" -EdgeTraversalPolicy DeferToUser -Protocol TCP -Program "$path\bin\javaw.exe"
    New-NetFirewallRule -DisplayName "Java(TM) Platform SE binary" -Enabled True -Profile Domain -Direction Inbound -Action Allow -Description "Java(TM) Platform SE binary" -EdgeTraversalPolicy DeferToUser -Protocol UDP -Program "$path\bin\javaw.exe"
    Write-Log "Add JAVA_HOME System Environment Variable with value '$path'"
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $path, "Machine")
}
