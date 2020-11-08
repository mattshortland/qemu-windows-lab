#! /usr/bin/pwsh

<#

Valid Roles

DomainController - The first Domain Controller in the list becomes the primary - At least one must be specified
SCCMServer - Only a single SCCM Server can be specified - It will install all roles for the server but will not install SQL or SCCM
Router - Currently you cannot automate a pfSense setup, but if you want to use this as a router add it - otherwise it will set the .1 IP address as router and enable NAT
MemberServer - Will domain join a server
Workstation - Will domain join a workstation

EXAMPLE CSV FILE

name,mac,role,IP,OS,OSBit,UEFIorBIOS,vcpu,ram,disk
Router,52:54:00:44:66:00,Router,1, pfsense,32,BIOS,1,2048,5
DC1,52:54:00:44:66:01,DomainController,2,win2k19,64,UEFI,2,4096,40
SCCM1,52:54:00:44:66:02,SCCMServer,3,win2k16,64,UEFI,2,4096,40
SRV1,52:54:00:44:66:03,Memberserver,DHCP,win2k12r2,64,UEFI,2,4096,40
WKS1,52:54:00:44:66:04,Workstation,DHCP,win10,64,UEFI,2,4096,40
WKS2,52:54:00:44:66:05,Workstation,DHCP,win8.1,64,UEFI,2,4096,40
DC2,52:54:00:44:66:06,DomainController,2,win2k19,64,UEFI,2,4096,40

Notes - OS must match the KVM default names
      - IP you must specify only the last octet
      - Validation will occur with the OS Version, UEFI and Bitness of the OS - if you try to install for example a 32-bit version of Server 2019 it will fail

#>



#Region Setup variables for build environment
Set-Location $PSScriptroot

$buildlist = Import-Csv $PSScriptroot/buildlist.csv

#Guest Specific Variables - setup as necessary
$AdministratorPasswordValue = 'P@ssword'
$oslanguageandlocale = "en-gb"
$numberofautologons = "3"
$subnet = "10.90.0.0/24" #Format Network/Mask e.g 192.168.1.0/24
$netbiosname = "short" #Max 16 Characters
$domainname = "short.land"

#Host Specific Variables
$QEMUNetwork = "DMZ" # only alphanumeric no spaces . - or _
$QEMUBridgeName = "virbr97" # Only change if you already have a network using this bridge
$VirtInstallArgs = '--features kvm_hidden=on,hyperv_relaxed=on,hyperv_vapic=on,hyperv_spinlocks=on,hyperv_spinlocks_retries=8191 --cpu EPYC' # Add any additional arguments 
$startupdelay = 7 # set a delay if you are installing a DC as part of this script

#Below OS Versions must match the Caption as displayed in Dism get-wiminfo to enable automatic choice of the OS version in Unattend.xml
$Windows10Version = "Windows 10 Enterprise"
$Windows81Version = "Windows 8.1 Enterprise"
$Windows8Version = "Windows 8 Enterprise"
$Windows7Version = "Windows 7 Enterprise"
$Windows7Version = "Windows 7 Enterprise"
$WindowsVistaVersion = "Windows Vista Ultimate"
$WindowsServer2019Version = "Windows Server 2019 SERVERSTANDARD"
$WindowsServer2016Version = "Windows Server 2016 SERVERSTANDARD"
$WindowsServer2012R2Version = "Windows Server 2012 R2 SERVERSTANDARD"
$WindowsServer2012Version = "Windows Server 2012 SERVERSTANDARD"
$WindowsServer2008R2Version = "Windows Server 2012 SERVERSTANDARD"
$WindowsServer2008Version = "Windows Server 2012 SERVERSTANDARD"

#endregion

#region generate Computer Info

$vnetwork = (($subnet  -split "\/" | Select-Object -First 1) -split "\." | Select-Object -First 3) -join "."
$vnetmask = $subnet  -split "\/" | Select-Object -Last 1
$domaincanonical = (($domainname -split "\.")| ForEach-Object { "DC=$_"}) -join ","
$Router = $buildlist | Where-Object {$_.role -eq "Router"} | Select-Object -First 1
$PrimaryDC = $buildlist | Where-Object {$_.role -eq "DomainController"} | Select-Object -First 1
$SecondaryDCs = $buildlist | Where-Object {$_.role -eq "DomainController"} | Select-Object -Skip 1
$SCCMServer = $buildlist | Where-Object {$_.role -eq "SCCMServer"} | Select-Object -First 1
$Memberservers = $buildlist | Where-Object {$_.role -eq "Memberserver"} 
$Workstations = $buildlist | Where-Object {$_.role -eq "Workstation"} 

if ($Router -ne $null)
    {
        $QEMUDefineNetwork = @"
<network>
    <name>$QEMUNetwork</name>
    <bridge name="$QEMUBridgeName" stp="on" delay="0"/>
    <domain name="$QEMUNetwork"/>
</network>
"@
    }

    else 
    {
        $QEMUDefineNetwork = @"
<network>
  <name>$QEMUNetwork</name>
  <forward mode="nat">
    <nat>
      <port start="1024" end="65535"/>
    </nat>
  </forward>
  <bridge name="$QEMUBridgeName" stp="on" delay="0"/>
  <mac address="52:54:00:$("0", "1", "2", "3", "4", "5", "6", "7", "8", "A", "B", "C", "D", "E", "F" | Get-Random)$("0", "1", "2", "3", "4", "5", "6", "7", "8", "A", "B", "C", "D", "E", "F" | Get-Random):$("0", "1", "2", "3", "4", "5", "6", "7", "8", "A", "B", "C", "D", "E", "F" | Get-Random)$("0", "1", "2", "3", "4", "5", "6", "7", "8", "A", "B", "C", "D", "E", "F" | Get-Random):$("0", "1", "2", "3", "4", "5", "6", "7", "8", "A", "B", "C", "D", "E", "F" | Get-Random)$("0", "1", "2", "3", "4", "5", "6", "7", "8", "A", "B", "C", "D", "E", "F" | Get-Random)"/>
  <domain name="$QEMUNetwork"/>
  <ip address="$vnetwork.1" netmask="255.255.255.0">
  </ip>
</network>
"@

$Router = [pscustomobject]@{
    IP = '1'
    }

    }

    $QEMUDefineNetwork | Out-File -FilePath "$PSScriptroot/Toolkit/HostScripts/network.xml" -Force

    $checknetwork = virsh net-list --all
    if ($checknetwork -notmatch $QEMUNetwork)
        {
            Start-Process "virsh" -ArgumentList "net-define --file $PSScriptroot/Toolkit/HostScripts/network.xml" -Wait
            Start-Process "virsh" -ArgumentList "net-start $QEMUNetwork" -Wait
            Start-Process "virsh" -ArgumentList "net-autostart $QEMUNetwork" -Wait
        }
    
    

#endregion

#region create directory structureon parameters for non-existent path

New-Item -ItemType Directory "$PSScriptroot/Toolkit" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/Downloads" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/Scripts" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/HostScripts" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win10-32" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win10-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win8.1-32" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win8.1-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win8-32" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win8-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win7-32" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win7-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/winvista" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k19-64"  -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k16-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k12r2-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k12-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k8r2-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k8-32" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/VirtIODrivers/win2k8-64" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/Toolkit/Certificates" -ErrorAction SilentlyContinue 
New-Item -ItemType Directory "$PSScriptroot/Toolkit/QEMUGuestAgent" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/ISOBuild" -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$PSScriptroot/ISO" -ErrorAction SilentlyContinue

#endregion
#region sort ISO files

$isofiles = Get-ChildItem -Path $PSScriptroot -Filter *.iso | Where-Object {$_.name -notlike "*-bit-setup.iso"}

foreach ($isofile in $isofiles)
    {
        if ($isofile.basename -like "*_10_*" -and $isofile.basename -like "*64BIT*" -or $isofile.basename -eq "win10" ) {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win10.iso" }
        if ($isofile.basename -like "*8.1_64BIT*" -or $isofile.basename -eq "win8.1") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win8.1.iso" }
        if ($isofile.basename -like "*8_64BIT*" -or $isofile.basename -eq "win8") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win8.iso" }
        if ($isofile.basename -like "*7_64BIT*" -or $isofile.basename -eq "win7") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win7.iso" }
        if ($isofile.basename -like "*2019*" -or $isofile.basename -eq "win2k19") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win2k19.iso" }
        if ($isofile.basename -like "*2016*" -or $isofile.basename -eq "win2k16") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win2k16.iso" }
        if ($isofile.basename -like "*2012_R2_64*" -or $isofile.basename -eq "win2k12r2") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win2k12r2.iso" }
        if ($isofile.basename -like "*2012_64*" -or $isofile.basename -eq "win2k12") {Move-Item $isofile.fullname -Destination "$PSScriptroot/ISO/win2k12.iso" }
    }

#endregion

function CreateBootISO {
    [Cmdletbinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("win7","win8","win8.1","win10","win2k8","win2k8r2","win2k12","win2k12r2","win2k16","win2k19")] 
        [string]$OSType,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("UEFI","BIOS")]
        [string]$UEFIorBIOS,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("32","64")]
        [string]$OSBase
    )
    
Begin {}

Process {
#region create autounattend.xml
if (Test-Path "$PSScriptroot/Toolkit/Scripts/")
{Remove-Item "$PSScriptroot/Toolkit/Scripts/*" -Force -Recurse}
if (Test-Path "$PSScriptroot/ISOBuild/")
{Remove-Item "$PSScriptroot/ISOBuild/*" -Force -Recurse}

$uefidiskconfig = @'
<DiskConfiguration>
                <Disk wcm:action="add">
                    <CreatePartitions>
                        <CreatePartition wcm:action="add">
                            <Order>1</Order>
                            <Size>200</Size>
                            <Type>EFI</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>2</Order>
                            <Size>128</Size>
                            <Type>MSR</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Extend>true</Extend>
                            <Order>3</Order>
                            <Type>Primary</Type>
                        </CreatePartition>
                    </CreatePartitions>
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                </Disk>
                <WillShowUI>OnError</WillShowUI>
                <DisableEncryptedDiskProvisioning>true</DisableEncryptedDiskProvisioning>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/NAME</Key>
                            <Value>OPERATINGSYSTEMIMAGENAME</Value>
                        </MetaData>
                    </InstallFrom>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>3</PartitionID>
                    </InstallTo>
                </OSImage>
            </ImageInstall>
'@


$biosdiskconfig = @'
                <DiskConfiguration>
                    <WillShowUI>OnError</WillShowUI>
                    <Disk wcm:action="add">
                        <DiskID>0</DiskID>
                        <WillWipeDisk>true</WillWipeDisk>
                        <CreatePartitions>
                            <CreatePartition wcm:action="add">
                                <Order>1</Order>
                                <Type>Primary</Type>
                                <Size>100</Size>
                            </CreatePartition>
                            <CreatePartition wcm:action="add">
                                <Order>2</Order>
                                <Type>Primary</Type>
                                <Extend>true</Extend>
                            </CreatePartition>
                            </CreatePartitions>
                            <ModifyPartitions>
                            <ModifyPartition wcm:action="add">
                                <Format>NTFS</Format>
                                <Label>System Reserved</Label>
                                <Order>1</Order>
                                <Active>true</Active>
                                <PartitionID>1</PartitionID>
                                <TypeID>0x27</TypeID>
                            </ModifyPartition>
                            <ModifyPartition wcm:action="add">
                                <Active>true</Active>
                                <Format>NTFS</Format>
                                <Label>OS</Label>
                                <Letter>C</Letter>
                                <Order>2</Order>
                                <PartitionID>2</PartitionID>
                            </ModifyPartition>
                        </ModifyPartitions>
                    </Disk>
                </DiskConfiguration>
                <ImageInstall>
                    <OSImage>
                        <InstallFrom>
                            <MetaData wcm:action="add">
                                <Key>/IMAGE/NAME</Key>
                                <Value>OPERATINGSYSTEMIMAGENAME</Value>
                            </MetaData>
                        </InstallFrom>
                        <InstallTo>
                            <DiskID>0</DiskID>
                            <PartitionID>2</PartitionID>
                        </InstallTo>
                        <WillShowUI>OnError</WillShowUI>
                        <InstallToAvailablePartition>false</InstallToAvailablePartition>
                    </OSImage>
                </ImageInstall>
'@


$autounattendbase = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Description>Load VIOSTOR Drivers</Description>
                    <Order>1</Order>
                    <Path>drvload.exe "E:\VirtIODrivers\OPERATINGSYSTEMVIOSTORDRIVERS\viostor.inf"</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Description>Load VIOSTOR Drivers</Description>
                    <Order>2</Order>
                    <Path>drvload.exe "E:\VirtIODrivers\OPERATINGSYSTEMVIOSTORDRIVERS\vioscsi.inf"</Path>
                </RunSynchronousCommand>
        </RunSynchronous>
DISKCONFIGURATIONANDIMAGEINSTALL
            <UserData>
                <ProductKey>
                    <WillShowUI>Never</WillShowUI>
                </ProductKey>
                <AcceptEula>true</AcceptEula>
            </UserData>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
DISKCONFIGURATIONANDIMAGEINSTALL
                    <UserData>
                        <ProductKey>
                            <WillShowUI>Never</WillShowUI>
                        </ProductKey>
                        <AcceptEula>true</AcceptEula>
                    </UserData>
                </component>
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SetupUILanguage>
                <UILanguage>en-us</UILanguage>
                <WillShowUI>Never</WillShowUI>
            </SetupUILanguage>
            <InputLocale>OSLANGUAGEANDLOCALE</InputLocale>
            <SystemLocale>OSLANGUAGEANDLOCALE</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>OSLANGUAGEANDLOCALE</UserLocale>
        </component>
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <SetupUILanguage>
            <UILanguage>en-us</UILanguage>
            <WillShowUI>Never</WillShowUI>
        </SetupUILanguage>
        <InputLocale>OSLANGUAGEANDLOCALE</InputLocale>
        <SystemLocale>OSLANGUAGEANDLOCALE</SystemLocale>
        <UILanguage>en-us</UILanguage>
        <UILanguageFallback>en-us</UILanguageFallback>
        <UserLocale>OSLANGUAGEANDLOCALE</UserLocale>
    </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>ADMINISTRATORPASSWORDVALUE</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>NUMBEROFAUTOLOGONS</LogonCount>
                <Username>administrator</Username>
            </AutoLogon>
           <TimeZone>GMT Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <AutoLogon>
            <Password>
                <Value>ADMINISTRATORPASSWORDVALUE</Value>
                <PlainText>true</PlainText>
            </Password>
            <Enabled>true</Enabled>
            <LogonCount>NUMBEROFAUTOLOGONS</LogonCount>
            <Username>administrator</Username>
        </AutoLogon>
       <TimeZone>GMT Standard Time</TimeZone>
    </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>OSLANGUAGEANDLOCALE</InputLocale>
            <SystemLocale>OSLANGUAGEANDLOCALE</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>OSLANGUAGEANDLOCALE</UserLocale>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>OSLANGUAGEANDLOCALE</InputLocale>
            <SystemLocale>OSLANGUAGEANDLOCALE</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>OSLANGUAGEANDLOCALE</UserLocale>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>ADMINISTRATORPASSWORDVALUE</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
                <LocalAccounts>
                <LocalAccount wcm:action="add">
                <Password>
                <Value>ADMINISTRATORPASSWORDVALUE</Value>
                <PlainText>true</PlainText>
                </Password>
                <Description></Description>
                <DisplayName>SetupUser</DisplayName>
                <Group>Administrators</Group>
                <Name>SetupUser</Name>
                </LocalAccount>
            </LocalAccounts>
            </UserAccounts>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>cmd /c reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Bypass /f</CommandLine>
                    <Order>2</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>cmd /c xcopy E:\ C:\setup\ /E/H/C/I</CommandLine>
                    <Order>3</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>4</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>5</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File c:\Setup\Setup.ps1</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>mkdir c:\setup</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>6</Order>
                    <CommandLine>reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff /f</CommandLine>
                </SynchronousCommand>
            </FirstLogonCommands>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>1</ProtectYourPC>
                <SkipUserOOBE>true</SkipUserOOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>ADMINISTRATORPASSWORDVALUE</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
                <LocalAccounts>
                <LocalAccount wcm:action="add">
                <Password>
                <Value>ADMINISTRATORPASSWORDVALUE</Value>
                <PlainText>true</PlainText>
                </Password>
                <Description></Description>
                <DisplayName>SetupUser</DisplayName>
                <Group>Administrators</Group>
                <Name>SetupUser</Name>
                </LocalAccount>
            </LocalAccounts>
            </UserAccounts>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>cmd /c reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Bypass /f</CommandLine>
                    <Order>2</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>cmd /c xcopy E:\ C:\setup\ /E/H/C/I</CommandLine>
                    <Order>3</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>4</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>5</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File c:\Setup\Setup.ps1</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                    <CommandLine>mkdir c:\setup</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>6</Order>
                    <CommandLine>reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff /f</CommandLine>
                </SynchronousCommand>
            </FirstLogonCommands>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>1</ProtectYourPC>
                <SkipUserOOBE>true</SkipUserOOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>OSLANGUAGEANDLOCALE</InputLocale>
            <SystemLocale>OSLANGUAGEANDLOCALE</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>OSLANGUAGEANDLOCALE</UserLocale>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>OSLANGUAGEANDLOCALE</InputLocale>
            <SystemLocale>OSLANGUAGEANDLOCALE</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>OSLANGUAGEANDLOCALE</UserLocale>
        </component>
    </settings>
    <settings pass="auditSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>ADMINISTRATORPASSWORDVALUE</Value> 
                    <PlainText>true</PlainText> 
                </Password>
                <Username>Administrator</Username> 
                    <Enabled>true</Enabled> 
                    <LogonCount>NUMBEROFAUTOLOGONS</LogonCount> 
            </AutoLogon>
            <UserAccounts>
                <AdministratorPassword>
                <Value>ADMINISTRATORPASSWORDVALUE</Value> 
                <PlainText>true</PlainText> 
                </AdministratorPassword>
            </UserAccounts>
            <FirstLogonCommands>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd /c reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Bypass /f</CommandLine>
                <Order>2</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd /c xcopy E:\ C:\setup\ /E/H/C/I</CommandLine>
                <Order>3</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>4</Order>
                <RequiresUserInput>false</RequiresUserInput>
                <CommandLine>powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c</CommandLine>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>5</Order>
                <RequiresUserInput>false</RequiresUserInput>
                <CommandLine>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File c:\Setup\Setup.ps1</CommandLine>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>1</Order>
                <RequiresUserInput>false</RequiresUserInput>
                <CommandLine>mkdir c:\setup</CommandLine>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>6</Order>
                <CommandLine>reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff /f</CommandLine>
            </SynchronousCommand>
        </FirstLogonCommands>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="x86" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>ADMINISTRATORPASSWORDVALUE</Value> 
                    <PlainText>true</PlainText> 
                </Password>
                <Username>Administrator</Username> 
                    <Enabled>true</Enabled> 
                    <LogonCount>NUMBEROFAUTOLOGONS</LogonCount> 
            </AutoLogon>
            <UserAccounts>
                <AdministratorPassword>
                <Value>ADMINISTRATORPASSWORDVALUE</Value> 
                <PlainText>true</PlainText> 
                </AdministratorPassword>
            </UserAccounts>
            <FirstLogonCommands>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd /c reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Bypass /f</CommandLine>
                <Order>2</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <CommandLine>cmd /c xcopy E:\ C:\setup\ /E/H/C/I</CommandLine>
                <Order>3</Order>
                <RequiresUserInput>false</RequiresUserInput>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>4</Order>
                <RequiresUserInput>false</RequiresUserInput>
                <CommandLine>powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c</CommandLine>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>5</Order>
                <RequiresUserInput>false</RequiresUserInput>
                <CommandLine>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File c:\Setup\Setup.ps1</CommandLine>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>1</Order>
                <RequiresUserInput>false</RequiresUserInput>
                <CommandLine>mkdir c:\setup</CommandLine>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
                <Order>6</Order>
                <CommandLine>reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff /f</CommandLine>
            </SynchronousCommand>
        </FirstLogonCommands>
        </component>
    </settings>
</unattend>
'@


<#
$VALID_OS = "win7","win8","win8.1","win10","win2k8","win2k8r2","win2k12","win2k12r2","win2k16","win2k19"
$VALID_BIOS = "win7","win8","win8.1","win10","win2k8","win2k8r2","win2k12","win2k12r2","win2k16","win2k19"
$VALID_UEFI = "win8","win8.1","win10","win2k8","win2k8r2","win2k12","win2k12r2","win2k16","win2k19"


$check = $false
while ($check -eq $false)
    {
        $OSType = read-host "Enter The Operating System"
        $UEFIorBIOS = Read-Host "Enter partitioning(UEFI or BIOS)"

        if ($VALID_OS -contains $OSType)
            {
                if ($UEFIorBIOS -eq "uefi")
                    {
                        if ($VALID_UEFI -contains $OSType)
                        {   
                            $check = $true
                        }
                        else {Write-Host "$OSType does not support UEFI"}
                    }
                elseif ($UEFIorBIOS -eq "bios")
                    {
                        if ($VALID_BIOS -contains $OSType)
                        { 
                            $check = $true
                        }
                        else {Write-Host "$OSType does not support BIOS"}
                    }
                else { Write-Host "Invalid option please choose UEFI or BIOS"}
            }
        else 
            {  
                Write-Host "Invalid OS type - ensure you are using libvirt values (valid options are : $VALID_OS)"
                Return    
            }
    }
$checkbase = $false
while ($checkbase -eq $false)
    {
        $OSBase = read-host "Enter 32 or 64 to choose your OS base version"
 
        if ($OSBase -eq "32" -or $OSBase -eq "64")
            { $checkbase = $true}
    }

#>    

if ($UEFIorBIOS -eq "uefi")
    {
        $autounattendbase = $autounattendbase -replace "DISKCONFIGURATIONANDIMAGEINSTALL", $uefidiskconfig`
    }
else {
    $autounattendbase = $autounattendbase -replace "DISKCONFIGURATIONANDIMAGEINSTALL", $biosdiskconfig`
    }
        
if ($OSType -eq "win10")
    {   
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $Windows10Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`
    }
if ($OSType -eq "win8.1")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $Windows81Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`
        
    }
if ($OSType -eq "win8")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $Windows8Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win7")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $Windows7Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win2k19")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $WindowsServer2019Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win2k16")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $WindowsServer2016Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win2k12r2")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $WindowsServer2012R2Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win2k12")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $WindowsServer2012Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win2k8r2")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $WindowsServer2008R2Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
if ($OSType -eq "win2k8")
    {
        $autounattendbase = $autounattendbase -replace "ADMINISTRATORPASSWORDVALUE", $AdministratorPasswordValue`
        -replace 'OPERATINGSYSTEMIMAGENAME', $WindowsServer2008Version `
        -replace 'OSLANGUAGEANDLOCALE', $oslanguageandlocale `
        -replace 'NUMBEROFAUTOLOGONS', $numberofautologons `
        -replace 'OPERATINGSYSTEMVIOSTORDRIVERS', "$ostype-$osbase"`

    }
#endregion

#region create powershell logon script

$setupbase = @'
#pause before starting
start-sleep -seconds 15

$OS = (Get-WmiObject win32_operatingsystem)

#region Enable Remote Connections (Install SSH and enable RDP)

if (($OS | Select-Object -expandproperty OSArchitecture) -eq "64-bit")
    {
        New-Item -ItemType Directory -Path "$env:ProgramFiles\OpenSSH"
        copy-item -Path "c:\Setup\OpenSSH-Win64\*" -Destination "$env:ProgramFiles\OpenSSH" -Recurse -Force
    }
else
    {
        New-Item -ItemType Directory -Path "$env:ProgramFiles\OpenSSH"
        copy-item -Path "c:\Setup\OpenSSH-Win32" -Destination "$env:ProgramFiles\OpenSSH" -Recurse -Force
    }

start-sleep -Seconds 2
powershell.exe -executionpolicy bypass -noprofile -file 'C:\Program Files\OpenSSH\install-sshd.ps1'
start-sleep -Seconds 2
netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=22
Start-Service sshd
Set-Service sshd -StartupType Automatic
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShellCommandOption -Value "/c" -PropertyType String -Force

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

#endregion

#region install certificates and VirtIODrivers

Function Import-Certificate
    {
        [cmdletbinding(SupportsShouldProcess=$True)]
        Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('PSComputername','__Server','IPAddress')]
        [string[]]$Computername =   $env:COMPUTERNAME,
        [parameter(Mandatory=$True)]
        [string]$Certificate,
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName =  'TrustedPublisher',
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation  = 'LocalMachine'
        )
    
        Begin 
            {
                $CertificateObject = New-Object  System.Security.Cryptography.X509Certificates.X509Certificate2
                $CertificateObject.Import($Certificate)
            }
            
        Process  
            {
                ForEach  ($Computer in  $Computername) 
                    {
                        $CertStore  = New-Object   System.Security.Cryptography.X509Certificates.X509Store  -ArgumentList  "\\$($Computername)\$($StoreName)", $StoreLocation
                        $CertStore.Open('ReadWrite')
                        If  ($PSCmdlet.ShouldProcess("$($StoreName)\$($StoreLocation)","Add  $Certificate")) 
                            {
                                $CertStore.Add($CertificateObject)
                            }
                    }
            }
    }

$VMCerts = Get-ChildItem -Path $PSScriptRoot\certificates\ -Filter "*.cer"
foreach  ($vmcert in $vmcerts)
    {
        Import-Certificate -Certificate $vmcert.FullName
    }

Start-Sleep -Seconds 2

if ($OS.Caption -like "*Windows 10*" -and $OS.OSArchitecture -eq "64-bit" )
	{ Get-ChildItem "$PSScriptRoot/VirtIODrivers/win10-64" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait } }
elseif ($OS.Caption -like "*Windows 8.1*" -and $OS.OSArchitecture -eq "64-bit" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win8.1-64" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows 8 *" -and $OS.OSArchitecture -eq "64-bit" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win8-64" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows 7*" -and $OS.OSArchitecture -eq "64-bit" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win7-64" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows 10*" -and $OS.OSArchitecture -eq "32-bit" )
	{ Get-ChildItem "$PSScriptRoot/VirtIODrivers/win10-32" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait } }
elseif ($OS.Caption -like "*Windows 8.1*" -and $OS.OSArchitecture -eq "32-bit" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win8.1-32" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows 8 *" -and $OS.OSArchitecture -eq "32-bit" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win8-32" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows 7*" -and $OS.OSArchitecture -eq "32-bit" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win7-32" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows Server 2019*" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k19" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows Server 2016*" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k16" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows Server 2012R2*" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k12r2" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows Server 2012 *" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k12" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
elseif ($OS.Caption -like "*Windows Server 2008R2*" )
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k8r2-64" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
    elseif ($OS.Caption -like "*Windows Server 2008 *" -and $OS.OSArchitecture -eq "64-bit")
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k8-64" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
    elseif ($OS.Caption -like "*Windows Server 2008 *" -and $OS.OSArchitecture -eq "32-bit")
    { Get-ChildItem "$PSScriptRoot/VirtIODrivers/win2k8-32" -Recurse -Filter "*.inf" | ForEach-Object { start-process "PNPUtil.exe" -Argumentlist "/add-driver $_.FullName /install" -Wait  } }
#endregion

#region install guest tools

cmd.exe --% /C "c:\setup\SpiceGuestTools\spice-guest-tools-latest.exe" /S

if (($OS | Select-Object -expandproperty OSArchitecture) -eq "64-bit")
    {
        Start-Process msiexec.exe -ArgumentList "/i C:\Setup\QEMUGuestAgent\qemu-ga-x86_64.msi /qn" -wait
        Start-Process msiexec.exe -ArgumentList "/i c:\setup\SpiceWebDAV\spice-webdavd-x64-latest.msi /qn" -wait
    }
if (($OS | Select-Object -expandproperty OSArchitecture) -eq "32-bit")
    {
        Start-Process msiexec.exe -ArgumentList "/i C:\Setup\QEMUGuestAgent\qemu-ga-i386.msi /qn" -wait
        Start-Process msiexec.exe -ArgumentList "/i c:\setup\SpiceWebDAV\spice-webdavd-x86-latest.msi /qn" -wait
    }

#region OS Customization

$Adapter = Get-NetAdapter | where-object {$_.macaddress -like "*52-54-00*"}
$MAC = $Adapter.MACAddress -replace "-",":"

switch ($MAC) 

{

LISTOFMACHINESINBUILDLIST

}

#endregion

'@


#endregion

#region customize base setup based on buildlist.csv

$machinemacswitchblock = @()

if ($PrimaryDC -ne $null)
{$PrimaryDCConfig = @'

"PRIMARYDCMAC" { 

   $IP = "VNETWORK.DCIPADDRESS"
   $MaskBits = "VNETMASK"
   $Gateway = "VNETWORK.ROUTERIPADDRESS"
   $Dns = "VNETWORK.DCIPADDRESS"
   $IPType = "IPv4"
   If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false}
   If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false}
   $adapter | New-NetIPAddress -AddressFamily $IPType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $Gateway
   $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
   install-windowsfeature AD-Domain-Services, RSAT-ADDS, DHCP -IncludeManageMentTools
   $cred = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
   $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-2.ps1'
   $trigger =  New-ScheduledTaskTrigger -AtLogon
   $User = "Administrator"
   Register-ScheduledTask -Action $action -Trigger $trigger -User $User -TaskName "SecondLogon" -Description "Second Logon Script"
   Rename-Computer -NewName "THISPCHOSTNAME" -Restart
   }

'@
$PrimaryDCConfig = $PrimaryDCConfig -replace "PRIMARYDCMAC", $primarydc.mac`
-replace 'THISPCHOSTNAME', "$($PrimaryDC.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$machinemacswitchblock += $PrimaryDCConfig
}

if ($SecondaryDCs -ne $null)
    {
        foreach ($SecondaryDC in $SecondaryDCs)
            {
                $SecondaryDCConfig = @'

"SECONDARYDCMAC" { 

    $IP = "VNETWORK.SECONDARYDCIP"
    $MaskBits = "VNETMASK"
    $Gateway = "VNETWORK.ROUTERIPADDRESS"
    $Dns = "VNETWORK.DCIPADDRESS"
    $IPType = "IPv4"
    If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false}
    If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false}
    $adapter | New-NetIPAddress -AddressFamily $IPType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $Gateway
    $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
    install-windowsfeature AD-Domain-Services, RSAT-ADDS, DHCP -IncludeManageMentTools
    Import-Module ADDSDeployment
    $cred = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
    $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-2.ps1'
    $trigger =  New-ScheduledTaskTrigger -AtLogon
    $User = "Administrator"
    Register-ScheduledTask -Action $action -Trigger $trigger -User $User -TaskName "SecondLogon" -Description "Second Logon Script"
    $domainpassword = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
    $DomainCred = New-Object System.Management.Automation.PSCredential ("NETBIOSDOMAINNAME\Administrator", $domainpassword)
    Install-ADDSDomainController -SkipPreChecks -SafeModeAdministratorPassword $cred -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -InstallDns -Credential $DomainCred -DomainName "FULLYQUALIFIEDDOMAINNAME" -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true
    }

'@
$SecondaryDCConfig = $SecondaryDCConfig -replace "SECONDARYDCMAC", $SecondaryDC.mac`
-replace 'THISPCHOSTNAME', "$($SecondaryDC.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'SECONDARYDCIP', "$($SecondaryDC.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$machinemacswitchblock += $SecondaryDCConfig 
        }
    }

    if ($SCCMServer -ne $null)
{$SCCMServerConfig = @'

"SCCMSERVERMAC" {

   $IP = "VNETWORK.SCCMIPADDRESS"
   $MaskBits = "VNETMASK"
   $Gateway = "VNETWORK.ROUTERIPADDRESS"
   $Dns = "VNETWORK.DCIPADDRESS"
   $IPType = "IPv4"
   If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false}
   If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false}
   $adapter | New-NetIPAddress -AddressFamily $IPType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $Gateway
   $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
   $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-2.ps1'
   $trigger =  New-ScheduledTaskTrigger -AtLogon
   Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "SecondLogon" -Description "Second Logon Script"
   Add-WindowsFeature Web-Windows-Auth,Web-ISAPI-Ext,Web-Metabase,Web-WMI,BITS,RDC,NET-Framework-Features,Web-Asp-Net,Web-Asp-Net45,NET-HTTP-Activation,NET-Non-HTTP-Activ,Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Http-Redirect,Web-App-Dev,Web-Net-Ext,Web-Net-Ext45,Web-ISAPI-Filter,Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-HTTP-Tracing,Web-Security,Web-Filtering,Web-Performance,Web-Stat-Compression,Web-Mgmt-Console,Web-Scripting-Tools,Web-Mgmt-Compat
   $domainpassword = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
   $DomainCred = New-Object System.Management.Automation.PSCredential ("NETBIOSDOMAINNAME\Administrator", $domainpassword)
   Add-Computer -DomainName FULLYQUALIFIEDDOMAINNAME -NewName THISPCHOSTNAME -Credential $DomainCred -Restart -Force
       }

'@
$SCCMServerConfig = $SCCMServerConfig -replace "SCCMSERVERMAC", $SCCMServer.mac`
-replace 'THISPCHOSTNAME', "$($SCCMServer.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'SCCMIPADDRESS', "$($SCCMServer.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$machinemacswitchblock += $SCCMServerConfig
    }

    if ($Memberservers -ne $null)
    {
        foreach ($Memberserver in $Memberservers)
            {
                $MemberserverConfig = @'

"MEMBERSERVERMAC" {

    $DHCPTrue = "MEMBERSERVERIP"
    if ($DHCPTrue -ne "DHCP")
        {
            $IP = "VNETWORK.MEMBERSERVERIP"
            $MaskBits = "VNETMASK"
            $Gateway = "VNETWORK.ROUTERIPADDRESS"
            $Dns = "VNETWORK.DCIPADDRESS"
            $IPType = "IPv4"
            If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false}
            If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false}
            $adapter | New-NetIPAddress -AddressFamily $IPType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $Gateway
            $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
        }
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-2.ps1'
        $trigger =  New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "SecondLogon" -Description "Second Logon Script"
        $domainpassword = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
        $DomainCred = New-Object System.Management.Automation.PSCredential ("NETBIOSDOMAINNAME\Administrator", $domainpassword)
        Add-Computer -DomainName FULLYQUALIFIEDDOMAINNAME -NewName THISPCHOSTNAME -Credential $DomainCred -Restart -Force
    }

'@
$MemberserverConfig = $MemberserverConfig -replace "MEMBERSERVERMAC", $Memberserver.mac`
-replace 'THISPCHOSTNAME', "$($Memberserver.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'MEMBERSERVERIP', "$($Memberserver.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$machinemacswitchblock += $MemberserverConfig 
        }
    }

    if ($Workstations -ne $null)
    {
        foreach ($Workstation in $Workstations)
            {
                $WorkstationConfig = @'

"WORKSTATIONMAC" {

    $DHCPTrue = "WORKSTATIONIP"
    if ($DHCPTrue -ne "DHCP")
        {
            $IP = "VNETWORK.WORKSTATIONIP"
            $MaskBits = "VNETMASK"
            $Gateway = "VNETWORK.ROUTERIPADDRESS"
            $Dns = "VNETWORK.DCIPADDRESS"
            $IPType = "IPv4"
            If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {$adapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false}
            If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {$adapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false}
            $adapter | New-NetIPAddress -AddressFamily $IPType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $Gateway
            $adapter | Set-DnsClientServerAddress -ServerAddresses $DNS
        }
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-2.ps1'
        $trigger =  New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "SecondLogon" -Description "Second Logon Script"
        $domainpassword = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
        $DomainCred = New-Object System.Management.Automation.PSCredential ("NETBIOSDOMAINNAME\Administrator", $domainpassword)
        Add-Computer -DomainName FULLYQUALIFIEDDOMAINNAME -NewName THISPCHOSTNAME -Credential $DomainCred -Restart -Force
    }

'@

$WorkstationConfig = $WorkstationConfig -replace "WORKSTATIONMAC", $Workstation.mac`
-replace 'THISPCHOSTNAME', "$($Workstation.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'WORKSTATIONIP', "$($Workstation.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$machinemacswitchblock += $WorkstationConfig 
        }
    }

    


#region import certificates

<#
How to add other certificates

$Content = Get-Content -Path ./certificate.cer -AsByteStream
$Base64 = [System.Convert]::ToBase64String($Content)
$Base64 | Out-File ./encodedcertificate.txt
Assign that text string to a variable $Encoded
$Content = [System.Convert]::FromBase64String($Encoded)
Set-Content -Path ./decodedcertificate.cer -Value $Content -AsByteStream

#>

$redhat1 = 'MIIFBjCCA+6gAwIBAgIQVsbSZ63gf3LutGA7v4TOpTANBgkqhkiG9w0BAQUFADCBtDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAxMCBDQTAeFw0xNjAzMTgwMDAwMDBaFw0xODEyMjkyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEQMA4GA1UEBxMHUmFsZWlnaDEWMBQGA1UEChQNUmVkIEhhdCwgSW5jLjEWMBQGA1UEAxQNUmVkIEhhdCwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMA3SYpIcNIEzqqy1PNimjt3bVY1KuIuvDABkx8hKUG6rl9WDZ7ibcW6f3cKgr1bKOAeOsMSDu6i/FzB7Csd9u/a/YkASAIIw48q9iD4K6lbKvd+26eJCUVyLHcWlzVkqIEFcvCrvaqaU/YlX/antLWyHGbtOtSdN3FfY5pvvTbWxf8PJBWGO3nV9CVL1DMK3wSn3bRNbkTLttdIUYdgiX+q8QjbM/VyGz7nA9UvGO0nFWTZRdoiKWI7HA0Wm7TjW3GSxwDgoFb2BZYDDNSlfzQpZmvnKth/fQzNDwumhDw7tVicu/Y8E7BLhGwxFEaP0xZtENTpn+1f0TxPxpzL2zMCAwEAAaOCAV0wggFZMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9zZi5zeW1jYi5jb20vc2YuY3JsMGEGA1UdIARaMFgwVgYGZ4EMAQQBMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkMF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL3NmLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3NmLnN5bWNiLmNvbS9zZi5jcnQwHwYDVR0jBBgwFoAUz5mp6nsm9EvJjo/X8AUm7+PSp50wHQYDVR0OBBYEFL/39F5yNDVDib3B3Uk3I8XJSrxaMA0GCSqGSIb3DQEBBQUAA4IBAQDWtaW0Dar82t1AdSalPEXshygnvh87Rce6PnM2/6j/ijo2DqwdlJBNjIOU4kxTFp8jEq8oM5Td48p03eCNsE23xrZl5qimxguIfHqeiBaLeQmxZavTHPNM667lQWPAfTGXHJb3RTT4siowcmGhxwJ3NGP0gNKCPHW09x3CdMNCIBfYw07cc6h9+Vm2Ysm9MhqnVhvROj+AahuhvfT9K0MJd3IcEpjXZ7aMX78Vt9/vrAIUR8EJ54YGgQsF/G9Adzs6fsfEw5Nrk8R0pueRMHRTMSroTe0VAe2nvuUU6rVI30q8+UjQCxu/ji1/JnitNkUyOPyC46zL+kfHYSnld8U1'
$redhat2 = 'MIIE0zCCA7ugAwIBAgIQShePL66PyVO0HnwjH6XtkzANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFudGVjIENsYXNzIDMgU0hBMjU2IENvZGUgU2lnbmluZyBDQTAeFw0xNTExMzAwMDAwMDBaFw0xODEyMjkyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEQMA4GA1UEBxMHUmFsZWlnaDEWMBQGA1UEChQNUmVkIEhhdCwgSW5jLjEWMBQGA1UEAxQNUmVkIEhhdCwgSW5jLjCCASAwCwYJKoZIhvcNAQEBA4IBDwAwggEKAoIBAQC77K+PJdE6f1B6FkMFdLmkZpEPWXgFQ/XNhfvcm39q8T4iBfto3HvVzox0s/uhDp6JIXFuR9S+74hYjRvZs1Lu4dXQ6KEgLcmo9UqLf0XZSmkVciYN+Joh1I+ovoMjSCLzF6AYjDKsYoTMVpHFbE/+uiLS8H4FCbaHAJFVPi6kXCYn9RCgzqPsYQNzTVpAKdBvukgQzGZ5EcvC09JSbf/+Ua0sdR95f/FRpBtOJLFiXUmaSoLm3kvxW3zYxI3otMNPuZYK+I6aPDDpTdEZgNPcQkOTiT0lFZ0V3f4cx3Z+N+o40H2UOKL4IZ3Z2uTcDMr6NPhv97VLktk1DEbn3HNXAgMBAAGjggFiMIIBXjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc3Yuc3ltY2IuY29tL3N2LmNybDBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkMF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL3N2LnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3N2LnN5bWNiLmNvbS9zdi5jcnQwHwYDVR0jBBgwFoAUljtT8Hkzl699g+8uK8zKt4YecmYwHQYDVR0OBBYEFNIhW3BAcnz8Wh/DVwx07qmz7BhHMA0GCSqGSIb3DQEBCwUAA4IBAQBMYtmjHv4V+mMbZZeL0TYpqlSoMfxt89LnxuG7DCo+LrcDl6YdvVrVQuZ1hx3HV0HwjzFut/jEazmM8LiYliHYhHcvw3ffz+CPiZSnf+gBjy9coOiX3eSFhBj4BjkXEgdrNmiStVkMcZf9BgKbu+Xi9i8lzDHROwa/Fu0kY8MD+mEEaJljrUuCgMChIbbcIWQ4AytnGaJeGshoeBxWmVmacB/fSGYSDlcMAm9d2NZutZeOQjLMaPuegsmAQlF83Ne4vp8OcImO8sY8pMhPiSBzWcefvXpYREfgajKhTL9ROEGCXSXS7h3A1kpcbWVLGnHNOVntupOy1DIDCzqlx8+B'
$redhat3 = 'MIIE1jCCA76gAwIBAgIQXRDLGOs6eQCHg6t0d/nTGTANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTUwMwYDVQQDEyxTeW1hbnRlYyBDbGFzcyAzIFNIQTI1NiBDb2RlIFNpZ25pbmcgQ0EgLSBHMjAeFw0xODExMjcwMDAwMDBaFw0yMjAxMjUyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRcwFQYDVQQIDA5Ob3J0aCBDYXJvbGluYTEQMA4GA1UEBwwHUmFsZWlnaDEWMBQGA1UECgwNUmVkIEhhdCwgSW5jLjEWMBQGA1UEAwwNUmVkIEhhdCwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6tLWiLXZXnYDRc6y9qeQrnN59qP5xutjQ4AHZY/m9EaNMRzKOONgalW6YTQRrW6emIscqlweRzvDnrF4hv/u/SfIq16XLqdViL0tZjmFWYhijbtFP1cjEZNeS47m2YnQgTpTsKmZ5A66/oiqzg8ogNbxxilUOojQ+rjzhwsvfJAgnaGhOMeR81ca2YsgzFX3Ywf7iy6A/CtjHIOh78wcwR0MaJW6QvOhOaClVhHGtq8yIUA7k/3k8sCC4xIxci2UqFOXopw0EUvd/xnc5by8m7LYdDO048sOM0lASt2d4PKniOvUkU/LpqiFSYo/6272j+KRBDYCW2IgPCK5HWlZMCAwEAAaOCAV0wggFZMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9yYi5zeW1jYi5jb20vcmIuY3JsMGEGA1UdIARaMFgwVgYGZ4EMAQQBMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkMF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL3JiLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3JiLnN5bWNiLmNvbS9yYi5jcnQwHwYDVR0jBBgwFoAU1MAGIknrOUvdk+JcobhHdglyA1gwHQYDVR0OBBYEFG9GZUQmGAU3flEwvkNB0Dhx23xpMA0GCSqGSIb3DQEBCwUAA4IBAQBX36ARUohDOhdV52T3imb+YRVdlm4k9eX4mtE/Z+3vTuQGeCKgRFo10w94gQrRCRCQdfeyRsJHSvYFbgdGf+NboOxX2MDQF9ARGw6DmIezVvNJCnngv19ULo1VrDDH9tySafmb1PFjkYwcl8a/i2MWQqM/erney9aHFHGiWiGfWu8GWc1fmnZdG0LjlzLWn+zvYKmRE30v/Hb8rRhXpEAUUvaB4tNo8ahQCl00nEBsr7tNKLabf9OfxXLp3oiMRfzWLBG4TavH5gWS5MgXBiP6Wxidf93vMkM3kaYRRj+33lHdchapyKtWzgvhHa8kjDBB5oOXYhc08zqbfMpf9vNm'

$Content = [System.Convert]::FromBase64String($redhat1)
Set-Content -Path "$psscriptroot/Toolkit/Certificates/redhat1.cer" -Value $Content -AsByteStream

$Content = [System.Convert]::FromBase64String($redhat2)
Set-Content -Path "$psscriptroot/Toolkit/Certificates/redhat2.cer" -Value $Content -AsByteStream

$Content = [System.Convert]::FromBase64String($redhat3)
Set-Content -Path "$psscriptroot/Toolkit/Certificates/redhat3.cer" -Value $Content -AsByteStream
#endregion

#Region Download Tools


$virtdrivers = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso"
$spicetools = "https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe"
$ssh64 = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.1.0.0p1-Beta/OpenSSH-Win64.zip"
$ssh32 = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.1.0.0p1-Beta/OpenSSH-Win32.zip"
$spicewebdavd64 = "https://www.spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi"
$spicewebdavd32 = "https://www.spice-space.org/download/windows/spice-webdavd/spice-webdavd-x86-latest.msi"

$urls = @()
$urls += $virtdrivers
$urls += $spicetools
$urls += $ssh64
$urls += $ssh32
$urls += $spicewebdavd64
$urls += $spicewebdavd32

foreach ($url in $urls)
    {
       $filename = $url -split "\/" | Select-Object -Last 1
              if (!(Test-Path "$psscriptroot/Toolkit/Downloads/$filename"))
            {
                Invoke-WebRequest -Uri $url -OutFile "$psscriptroot/Toolkit/Downloads/$filename"
            }
    }

#endregion

#Region Extract ISO/ZIPs and organize drivers


start-process -Filepath "xorriso" -Argumentlist '-acl on -xattr on -osirrox on -indev ./Toolkit/Downloads/virtio-win.iso -extract / ./Toolkit/virtio' -Wait
chmod -R u+w $PSScriptroot/Toolkit/virtio


$virtiofiles = Get-ChildItem $PSScriptroot/Toolkit/virtio -Attributes !Directory -Recurse
$virtiofiles | Where-Object {$_.FullName -like "*/w10/amd64/*" -or $_.FullName -like "*/amd64/w10/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win10-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w10/x86/*" -or $_.FullName -like "*/i386/w10/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win10-32" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w8.1/amd64/*" -or $_.FullName -like "*/amd64/w8.1/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win8.1-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w8.1/x86/*" -or $_.FullName -like "*/i386/w8.1/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win8.1-32" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w8/amd64/*" -or $_.FullName -like "*/amd64/w8/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win8-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w8/x86/*" -or $_.FullName -like "*/i386/w8/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win8-32" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w7/amd64/*" -or $_.FullName -like "*/amd64/w7/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win7-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w7/x86/*" -or $_.FullName -like "*/i386/w7/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win7-32" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/2k19/amd64/*" -or $_.FullName -like "*/amd64/2k19/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k19-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/2k16/amd64/*" -or $_.FullName -like "*/amd64/2k16/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k16-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/2k12R2/amd64/*" -or $_.FullName -like "*/amd64/2k12R2/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k12r2-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/2k12/amd64/*" -or $_.FullName -like "*/amd64/2k12/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k12-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w2k8R2/amd64/*" -or $_.FullName -like "*/amd64/w2k8R2/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k8R2-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/w2k8/amd64/*" -or $_.FullName -like "*/amd64/w2k8/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k8-64" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*/win2k8/x86/*" -or $_.FullName -like "*/i386/win2k8/*"} | copy-item -Destination "$PSScriptroot/Toolkit/VirtIODrivers/win2k8-32" -ErrorAction SilentlyContinue
$virtiofiles | Where-Object {$_.FullName -like "*qemu-ga-x86_64.msi*"} | copy-item -Destination $PSScriptroot/Toolkit/QEMUGuestAgent
$virtiofiles | Where-Object {$_.FullName -like "*qemu-ga-i386.msi*"} | copy-item -Destination $PSScriptroot/Toolkit/QEMUGuestAgent

if (!(test-path $PSScriptroot/Toolkit/OpenSSH-Win64))
    {
        start-process -FilePath "unzip" -ArgumentList "$psscriptroot/Toolkit/Downloads/OpenSSH-Win64.zip" -Wait
        Move-Item $PSScriptroot/OpenSSH-Win64 -Destination "$PSScriptroot/Toolkit" -Force
        start-process -FilePath "unzip" -ArgumentList "$psscriptroot/Toolkit/Downloads/OpenSSH-Win32.zip" -Wait
        Move-Item $PSScriptroot/OpenSSH-Win32 -Destination "$PSScriptroot/Toolkit" -Force
    }

#endregion

#region create second logon scripts for each machine

if ($PrimaryDC -ne $null)
{$PrimaryDCSecondLogonScript = @'

if (test-path "c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1" )
    {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1'
        $trigger =  New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "ThirdLogon" -Description "Third Logon Script"
    }

    Unregister-ScheduledTask -TaskName Secondlogon -Confirm:$false
$cred = ConvertTo-SecureString "ADMINISTRATORPASSWORDVALUE" -AsPlainText -Force
Import-Module ADDSDeployment
Install-ADDSForest -SkipPreChecks -SafeModeAdministratorPassword $cred -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012R2" -DomainName "FULLYQUALIFIEDDOMAINNAME" -DomainNetbiosName "NETBIOSDOMAINNAME" -ForestMode "Win2012R2" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true

'@
$PrimaryDCSecondLogonScript = $PrimaryDCSecondLogonScript -replace "PRIMARYDCMAC", $primarydc.mac`
-replace 'THISPCHOSTNAME', "$($PrimaryDC.name)" `
-replace 'SCCMHOSTNAME', "$($SCCMServer.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'DOMAINCANONICAL', "$domaincanonical" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$PrimaryDCSecondLogonScript | out-file "$PSScriptroot/Toolkit/Scripts/$($PrimaryDC.name)-Setup-2.ps1" -Force
}


if ($PrimaryDC -ne $null)
{$PrimaryDCThirdLogonScript = @'

Import-Module ActiveDirectory

add-DhcpServerInDC -DNSName THISPCHOSTNAME.FULLYQUALIFIEDDOMAINNAME -IPAddress VNETWORK.DCIPADDRESS
Add-DhcpServerV4Scope -name “NETBIOSDOMAINNAME” -StartRange VNETWORK.100 -Endrange VNETWORK.200 -SubnetMask 255.255.255.0 -State Active
Set-DhcpServerV4OptionValue -ComputerName THISPCHOSTNAME.FULLYQUALIFIEDDOMAINNAME -ScopeID VNETWORK.100 -DNSServer VNETWORK.DCIPADDRESS -Router VNETWORK.ROUTERIPADDRESS
Add-DnsServerForwarder -IPAddress VNETWORK.ROUTERIPADDRESS -PassThru
New-ADOrganizationalUnit -Name "UserAccounts" -Path "DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Groups" -Path "DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Servers" -Path "DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Administrators" -Path "DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Service" -Path "DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Endpoints" -Path "DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "SCCM" -Path "OU=Servers,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "London" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "New York" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Tokyo" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Sydney" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "SanFrancisco" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Moscow" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Singapore" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "Berlin" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADOrganizationalUnit -Name "SaoPaulo" -Path "OU=UserAccounts,DOMAINCANONICAL"
New-ADComputer -Name "SCCMHOSTNAME" -SamAccountName "SCCMHOSTNAME" -Path "OU=Servers,DOMAINCANONICAL" -Enabled $True
$Group = New-ADGroup -Name 'SCCM-Site-Servers' -GroupScope Universal -Path "OU=Groups,DOMAINCANONICAL" -passthru
Add-ADGroupMember -Identity 'SCCM-Site-Servers' -Members SCCMHOSTNAME$
New-ADObject -Name "System Management" -Type Container -Path ("CN=System,DOMAINCANONICAL") 
$CN = 'CN=System Management,CN=System,DOMAINCANONICAL'
$ACL = Get-Acl "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$CN"
$SID = New-Object System.Security.Principal.SecurityIdentifier $Group.SID
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "GenericAll", "Allow", "00000000-0000-0000-0000-000000000000", "All", "00000000-0000-0000-0000-000000000000"
$ACL.AddAccessRule($ACE)
Set-Acl "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$CN" -AclObject $ACL
Unregister-ScheduledTask -TaskName Thirdlogon -Confirm:$false


'@
$PrimaryDCThirdLogonScript = $PrimaryDCThirdLogonScript -replace "PRIMARYDCMAC", $primarydc.mac`
-replace 'THISPCHOSTNAME', "$($PrimaryDC.name)" `
-replace 'SCCMHOSTNAME', "$($SCCMServer.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'DOMAINCANONICAL', "$domaincanonical" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$PrimaryDCThirdLogonScript | out-file "$PSScriptroot/Toolkit/Scripts/$($PrimaryDC.name)-Setup-3.ps1" -Force
}

if ($SecondaryDCs -ne $null)
    {
$SecondaryDCSecondLogonScript = @'

    if (test-path "c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1" )
        {
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1'
            $trigger =  New-ScheduledTaskTrigger -AtLogon
            Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "ThirdLogon" -Description "Third Logon Script"
        }
    write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"
    Unregister-ScheduledTask -TaskName Secondlogon -Confirm:$false
    start-sleep -Seconds 60
    write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"

'@

$SecondaryDCConfig = $SecondaryDCConfig -replace "SECONDARYDCMAC", $SecondaryDC.mac`
-replace 'THISPCHOSTNAME', "$($SecondaryDC.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'SECONDARYDCIP', "$($SecondaryDC.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue

$PrimaryDCSecondLogonScript | out-file "$PSScriptroot/Toolkit/Scripts/$($SecondaryDC.name)-Setup-2.ps1" -Force

    }

    if ($SCCMServer -ne $null)
{$SCCMServerSecondLogonScript= @'

if (test-path "c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1" )
    {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1'
        $trigger =  New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "ThirdLogon" -Description "Third Logon Script"
    }
write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"
Unregister-ScheduledTask -TaskName Secondlogon -Confirm:$false
start-sleep -Seconds 60
write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"

'@

$SCCMServerSecondLogonScript = $SCCMServerSecondLogonScript -replace "SCCMSERVERMAC", $SCCMServer.mac`
-replace 'THISPCHOSTNAME', "$($SCCMServer.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'SCCMIPADDRESS', "$($SCCMServer.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue

$SCCMServerSecondLogonScript | out-file "$PSScriptroot/Toolkit/Scripts/$($SCCMServer.name)-Setup-2.ps1" -Force

    }

    if ($Memberservers -ne $null)
    {
            $MemberserverSecondLogonScript= @'

if (test-path "c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1" )
    {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1'
        $trigger =  New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "ThirdLogon" -Description "Third Logon Script"
    }
write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"
Unregister-ScheduledTask -TaskName Secondlogon -Confirm:$false
start-sleep -Seconds 60
write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"

'@

$MemberserverSecondLogonScript = $MemberserverSecondLogonScript -replace "MEMBERSERVERMAC", $Memberserver.mac`
-replace 'THISPCHOSTNAME', "$($Memberserver.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'MEMBERSERVERIP', "$($Memberserver.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue
$MemberserverSecondLogonScript | out-file "$PSScriptroot/Toolkit/Scripts/$($Memberserver.name)-Setup-2.ps1" -Force

    
    }

    if ($Workstations -ne $null)
    {
        $WorkstationSecondLogonScript = @'

if (test-path "c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1" )
    {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe'-Argument '-NoProfile -WindowStyle Hidden -File c:\Setup\Scripts\THISPCHOSTNAME-Setup-3.ps1'
        $trigger =  New-ScheduledTaskTrigger -AtLogon
        Register-ScheduledTask -Action $action -Trigger $trigger -User Administrator -TaskName "ThirdLogon" -Description "Third Logon Script"
    }
write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"
Unregister-ScheduledTask -TaskName Secondlogon -Confirm:$false
start-sleep -Seconds 60
write-host "You can modify this script in the vmsetup.ps1 file on the host under #region create second logon scripts for each machine"

'@

$WorkstationSecondLogonScript = $WorkstationSecondLogonScript -replace "WORKSTATIONMAC", $Workstation.mac`
-replace 'THISPCHOSTNAME', "$($Workstation.name)" `
-replace 'NETBIOSDOMAINNAME', "$netbiosname" `
-replace 'FULLYQUALIFIEDDOMAINNAME', "$domainname" `
-replace 'ROUTERIPADDRESS', "$($Router.IP)" `
-replace 'DCIPADDRESS', "$($PrimaryDC.IP)" `
-replace 'WORKSTATIONIP', "$($Workstation.IP)" `
-replace 'VNETWORK', "$vnetwork" `
-replace 'VNETMASK', "$vnetmask" `
-replace 'ADMINISTRATORPASSWORDVALUE', $AdministratorPasswordValue

$WorkstationSecondLogonScript | out-file "$PSScriptroot/Toolkit/Scripts/$($Workstation.name)-Setup-2.ps1" -Force

    }


#endregion

#region build ISO files for OS versions
$autounattendbase | Set-Content "$PSScriptroot/ISOBuild/autounattend.xml" -Force
$setupbase | Foreach-Object {$_ -replace 'LISTOFMACHINESINBUILDLIST', ($machinemacswitchblock) }| Set-Content "$PSScriptroot/ISOBuild/setup.ps1" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/Certificates" -Recurse -Destination "$PSScriptroot/ISOBuild" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/VirtIODrivers" -Recurse -Destination "$PSScriptroot/ISOBuild" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/OpenSSH-Win64" -Recurse -Destination "$PSScriptroot/ISOBuild" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/OpenSSH-Win32" -Recurse -Destination "$PSScriptroot/ISOBuild" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/QEMUGuestAgent" -Recurse -Destination "$PSScriptroot/ISOBuild" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/Scripts" -Recurse -Destination "$PSScriptroot/ISOBuild" -Force
New-Item -ItemType Directory "$PSScriptroot/ISOBuild/SpiceGuestTools" -Force
New-Item -ItemType Directory "$PSScriptroot/ISOBuild/SpiceWebDAV" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/Downloads/spice-guest-tools-latest.exe" -Destination "$PSScriptroot/ISOBuild/SpiceGuestTools" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/Downloads/spice-webdavd-x64-latest.msi" -Destination "$PSScriptroot/ISOBuild/SpiceWebDAV" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/Downloads/spice-webdavd-x86-latest.msi" -Destination "$PSScriptroot/ISOBuild/SpiceWebDAV" -Force
New-Item -ItemType Directory "$PSScriptroot/ISOBuild/`$WinPEDriver`$" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/VirtIODrivers/$OSType-$OSBase/vioscsi*" -Destination "$PSScriptroot/ISOBuild/`$WinPEDriver`$" -Force
Copy-Item -Path "$PSScriptroot/Toolkit/VirtIODrivers/$OSType-$OSBase/viostor*" -Destination "$PSScriptroot/ISOBuild/`$WinPEDriver`$" -Force


        if (Test-Path "$PSScriptroot/ISO/$OSType-setup.iso") {Remove-Item "$PSScriptroot/ISO/$OSTYPE-setup.iso" -Force}
        start-process -Filepath "xorrisofs" -Argumentlist "-r -J -o $PSScriptroot/ISO/$OSTYPE-$OSBase-bit-setup.iso $PSScriptroot/ISOBuild/" -Wait

Remove-Item "$PSScriptroot/Toolkit/Scripts/*" -Force -Recurse
Remove-Item "$PSScriptroot/ISOBuild/*" -Force -Recurse
#endregion
}

end {}
}




foreach ($computer in $buildlist)
    {
        CreateBootISO -OSType $computer.OS -UEFIorBIOS $Computer.UEFIorBIOS -OSBase $computer.OSBit

    }



#endregion


#region define Virtual Machines
foreach ($machine in $buildlist)
    {
        if (!(test-path $psscriptroot/$($machine.name).img ))
        {start-process "qemu-img" -ArgumentList "create -f raw -o preallocation=full $psscriptroot/$($machine.name).img $($machine.disk)G" -Wait}
    }

    foreach ($machine in $PrimaryDC)
        {
            start-process -filepath "virt-install" -ArgumentList "--virt-type=kvm --boot machine=q35 --boot uefi --name=$($machine.name) --ram=$($machine.ram) --vcpus=$($machine.vcpu) --os-type=windows --os-variant=$($machine.os) --iothreads=1 --disk $psscriptroot/$($machine.name).img,size=$($machine.disk),bus=virtio,format=,cache=writethrough,discard=unmap,io=threads --disk $psscriptroot/ISO/$($machine.os)-$($machine.OSBit)-bit-setup.iso,device=cdrom,bus=sata,readonly=on,shareable=on --cdrom=$psscriptroot/ISO/$($machine.os).iso --network=network=$QEMUNetwork,model=virtio,mac=$($machine.mac) --graphics=spice --clock hypervclock_present=yes $VirtInstallArgs"
            for ($i=1; $i -le 90; $i++)
                {
                    start-process "virsh" -ArgumentList "send-key $($machine.name) KEY_ENTER"
                    start-sleep -Milliseconds 200 
            }

            Write-Host "Waiting for Primary DC to install, remaining guests will be started and paused"
            Start-Sleep -Seconds 3
    }



foreach ($machine in ($buildlist | Where-Object {$_ -ne $PrimaryDC} | Where-Object {$_ -ne $Router}))
    {
        start-process -filepath "virt-install" -ArgumentList "--virt-type=kvm --boot machine=q35 --boot uefi --name=$($machine.name) --ram=$($machine.ram) --vcpus=$($machine.vcpu) --os-type=windows --os-variant=$($machine.os) --iothreads=1 --disk $psscriptroot/$($machine.name).img,size=$($machine.disk),bus=virtio,format=,cache=writethrough,discard=unmap,io=threads --disk $psscriptroot/ISO/$($machine.os)-$($machine.OSBit)-bit-setup.iso,device=cdrom,bus=sata,readonly=on,shareable=on --cdrom=$psscriptroot/ISO/$($machine.os).iso --network=network=$QEMUNetwork,model=virtio,mac=$($machine.mac) --graphics=spice --clock hypervclock_present=yes $VirtInstallArgs"
        for ($i=1; $i -le 30; $i++)
            {
                start-process "virsh" -ArgumentList "send-key $($machine.name) KEY_ENTER"
                start-sleep -Milliseconds 200 
            }
        
    start-sleep -seconds 3

    Start-Process "virsh" -ArgumentList "suspend $($machine.name)"
      
}


#endregion