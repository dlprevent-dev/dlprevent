<#
CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 for the lab clients (OU=Workstations,
isu.int): the checks Wazuh SCA reported as failed on DESKTOP-N498VCD on 2026-10-14, as one GPO.

  CIS - Workstations   linked at OU=Workstations

Run on the DC as Domain Admin, next to CisGpo.ps1. Re-running is safe: it rewrites the GPO.
Clients get it at their next policy refresh (or `gpupdate /force` on the client).
Password and lockout policy come from "CIS - Domain Account Policy" (Set-CisDcBaseline.ps1).
Check without the Wazuh manager: gen_verifier.py with the agent's cis_win11_enterprise.yml and
wazuh-failed-client-2026-10-14.txt (the IDs this script covers).

Checks that stay failed, and why (not applied because it breaks the DLP lab, or Wazuh can't see it):
  26083        sshd disabled          kept as the key-auth way in (RDP is the only other one)
  26088        Spooler disabled       the agent intercepts printing in Chrome/Edge/Firefox; print
                                      tests need a spooler. 26209 (no remote clients) is set.
  26091-26093  RDP services disabled  RDP is how the client is administered and tested
  26097        Server service off     breaks the \\127.0.0.1\c$ bypass test and admin shares
  26038        SMB SPN validation     level 1 can refuse \\127.0.0.1\c$ (NTLM sends cifs/127.0.0.1),
                                      which is a documented bypass test
  26203        disable IPv6           Microsoft advises against it, untested configuration
  26227, 26229 HVCI / CredGuard lock  "Enabled with UEFI lock" is one-way
  26230        kernel shadow stacks   enforcement mode crashes on incompatible drivers once VBS runs
  26270        LSASS PPL + UEFI lock  set to 2 (PPL without UEFI lock) instead
  26320-26327  BitLocker OS recovery  enabling recovery + AD DS backup lets Windows 11 finish
                                      automatic device encryption on the VM; then a lost vTPM or
                                      10 bad logons (26024) mean the recovery key at the console
  26349        deny write to USB      without BitLocker on the stick, USB copy tests can't happen
  26418        RDP drive redirection  also stops copying files over the RDP clipboard, a test channel
  26428, 26429 RDP idle / disconnect  idle drops the RDP clipboard channel mid-test; the disconnect
                                      limit logs off dl-anna's running test session
  26439        DisableStoreApps       on Enterprise it stops every Store app from starting, inbox
                                      ones included: Notepad, Calculator, Snipping Tool, Terminal
  26232, 26233, 26235, 26236          device-install restrictions are set as CIS means them, but
                                      Wazuh's rules treat values as subkeys and can never pass

Changed on purpose:
  26011        local Administrator renamed to "isu-wsroot" (Wazuh fails any local name that
               contains "admin")
  26261-26268  Windows LAPS backs up to AD - only works once the AD schema has the LAPS
               attributes (Update-LapsADSchema, one-way, not done by this script) and the OU
               lets computers write them (Set-LapsADComputerSelfPermission -Identity
               OU=Workstations,...). Until then LAPS logs errors and changes nothing; after,
               it owns the isu-wsroot password (Get-LapsADPassword on the DC).
#>
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\CisGpo.ps1"

# --- Security template: security options, the local Administrator name, service start types.
$Inf = @'
[System Access]
NewAdministratorName = "isu-wsroot"
[Service General Setting]
"BTAGService",4,""
"bthserv",4,""
"MapsBroker",4,""
"lfsvc",4,""
"lltdsvc",4,""
"MSiSCSI",4,""
"wercplsupport",4,""
"RasAuto",4,""
"RpcLocator",4,""
"SSDPSRV",4,""
"upnphost",4,""
"WerSvc",4,""
"Wecsvc",4,""
"WMPNetworkSvc",4,""
"icssvc",4,""
"WpnService",4,""
"PushToInstall",4,""
"WinRM",4,""
"XboxGipSvc",4,""
"XblAuthManager",4,""
"XblGameSave",4,""
"XboxNetApiSvc",4,""
[Registry Values]
MACHINE\System\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser=4,3
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts=4,10
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"ISU lab - authorized use only"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=1,"This system is for authorized ISU lab use only. Activity is logged and monitored."
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"4"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"1"
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483640
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
'@

# --- Advanced audit policy: CIS 17.x plus the Windows 11 defaults, so nothing that was on goes
# off. The client runs the agent's endpoint role, which reads no Security log events.
$Audit = @'
Security State Change|{0CCE9210-69AE-11D9-BED3-505054503030}|1
Security System Extension|{0CCE9211-69AE-11D9-BED3-505054503030}|1
System Integrity|{0CCE9212-69AE-11D9-BED3-505054503030}|3
IPsec Driver|{0CCE9213-69AE-11D9-BED3-505054503030}|3
Other System Events|{0CCE9214-69AE-11D9-BED3-505054503030}|3
Logon|{0CCE9215-69AE-11D9-BED3-505054503030}|3
Logoff|{0CCE9216-69AE-11D9-BED3-505054503030}|1
Account Lockout|{0CCE9217-69AE-11D9-BED3-505054503030}|3
Special Logon|{0CCE921B-69AE-11D9-BED3-505054503030}|1
Other Logon/Logoff Events|{0CCE921C-69AE-11D9-BED3-505054503030}|3
Group Membership|{0CCE9249-69AE-11D9-BED3-505054503030}|1
File Share|{0CCE9224-69AE-11D9-BED3-505054503030}|3
Other Object Access Events|{0CCE9227-69AE-11D9-BED3-505054503030}|3
Detailed File Share|{0CCE9244-69AE-11D9-BED3-505054503030}|2
Removable Storage|{0CCE9245-69AE-11D9-BED3-505054503030}|3
Sensitive Privilege Use|{0CCE9228-69AE-11D9-BED3-505054503030}|3
Process Creation|{0CCE922B-69AE-11D9-BED3-505054503030}|1
Plug and Play Events|{0CCE9248-69AE-11D9-BED3-505054503030}|1
Audit Policy Change|{0CCE922F-69AE-11D9-BED3-505054503030}|1
Authentication Policy Change|{0CCE9230-69AE-11D9-BED3-505054503030}|1
Authorization Policy Change|{0CCE9231-69AE-11D9-BED3-505054503030}|1
MPSSVC Rule-Level Policy Change|{0CCE9232-69AE-11D9-BED3-505054503030}|3
Other Policy Change Events|{0CCE9234-69AE-11D9-BED3-505054503030}|2
User Account Management|{0CCE9235-69AE-11D9-BED3-505054503030}|3
Security Group Management|{0CCE9237-69AE-11D9-BED3-505054503030}|1
Application Group Management|{0CCE9239-69AE-11D9-BED3-505054503030}|3
Network Policy Server|{0CCE9243-69AE-11D9-BED3-505054503030}|3
Credential Validation|{0CCE923F-69AE-11D9-BED3-505054503030}|3
'@

# --- Administrative templates and MSS values: Registry.pol. key | value | D(word) or S(tring) | data
$P  = 'SOFTWARE\Policies\Microsoft'
$PW = 'SOFTWARE\Policies\Microsoft\Windows'
$CV = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
$TS = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$WD = 'SOFTWARE\Policies\Microsoft\Windows Defender'
$PR = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$FW = 'SOFTWARE\Policies\Microsoft\WindowsFirewall'
$DI = 'SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
$Reg = @"
$FW\DomainProfile|DisableNotifications|D|1
$FW\DomainProfile\Logging|LogFilePath|S|%SystemRoot%\System32\logfiles\firewall\domainfw.log
$FW\DomainProfile\Logging|LogFileSize|D|16384
$FW\DomainProfile\Logging|LogDroppedPackets|D|1
$FW\DomainProfile\Logging|LogSuccessfulConnections|D|1
$FW\PrivateProfile|DisableNotifications|D|1
$FW\PrivateProfile\Logging|LogFilePath|S|%SystemRoot%\System32\logfiles\firewall\privatefw.log
$FW\PrivateProfile\Logging|LogFileSize|D|16384
$FW\PrivateProfile\Logging|LogDroppedPackets|D|1
$FW\PrivateProfile\Logging|LogSuccessfulConnections|D|1
$FW\PublicProfile|DisableNotifications|D|1
$FW\PublicProfile|AllowLocalPolicyMerge|D|0
$FW\PublicProfile|AllowLocalIPsecPolicyMerge|D|0
$FW\PublicProfile\Logging|LogFilePath|S|%SystemRoot%\System32\logfiles\firewall\publicfw.log
$FW\PublicProfile\Logging|LogFileSize|D|16384
$FW\PublicProfile\Logging|LogDroppedPackets|D|1
$FW\PublicProfile\Logging|LogSuccessfulConnections|D|1
$FW\FirewallRules|CIS-SSH-In|S|v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=22|Name=CIS keep SSH reachable|
$FW\FirewallRules|CIS-RDP-In|S|v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=CIS keep RDP reachable|
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon|CachedLogonsCount|S|4
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon|ScRemoveOption|S|1
SOFTWARE\Microsoft\Cryptography\Wintrust\Config|EnableCertPaddingCheck|D|1
SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config|EnableCertPaddingCheck|D|1
SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config|AutoConnectAllowedOEM|D|0
SOFTWARE\Wow6432Node\Microsoft\WcmSvc\wifinetworkmanager\config|AutoConnectAllowedOEM|D|0
$PW\Personalization|NoLockScreenCamera|D|1
$PW\Personalization|NoLockScreenSlideshow|D|1
$P\InputPersonalization|AllowInputPersonalization|D|0
$CV\Explorer|AllowOnlineTips|D|0
SYSTEM\CurrentControlSet\Control\Session Manager\kernel|DisableExceptionChainValidation|D|0
SYSTEM\CurrentControlSet\Services\NetBT\Parameters|NodeType|D|2
SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|DisableIPSourceRouting|D|2
SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|TcpMaxDataRetransmissions|D|3
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|DisableIPSourceRouting|D|2
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|EnableICMPRedirect|D|0
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|KeepAliveTime|D|300000
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|PerformRouterDiscovery|D|0
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|TcpMaxDataRetransmissions|D|3
SYSTEM\CurrentControlSet\Services\RasMan\Parameters|DisableSavePassword|D|1
$P\Windows NT\DNSClient|DoHPolicy|D|2
$P\Windows NT\DNSClient|EnableMulticast|D|0
$PW\System|EnableFontProviders|D|0
$PW\LanmanWorkstation|AllowInsecureGuestAuth|D|0
$P\Peernet|Disabled|D|1
$PW\Network Connections|NC_AllowNetBridge_NLA|D|0
$PW\Network Connections|NC_ShowSharedAccessUI|D|0
$PW\Network Connections|NC_StdDomainUserSetLocation|D|1
$PW\NetworkProvider\HardenedPaths|\\*\NETLOGON|S|RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1
$PW\NetworkProvider\HardenedPaths|\\*\SYSVOL|S|RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1
$PW\WCN\Registrars|EnableRegistrars|D|0
$PW\WCN\Registrars|DisableUPnPRegistrar|D|0
$PW\WCN\Registrars|DisableInBand802DOT11Registrar|D|0
$PW\WCN\Registrars|DisableFlashConfigRegistrar|D|0
$PW\WCN\Registrars|DisableWPDRegistrar|D|0
$PW\WCN\UI|DisableWcnUi|D|1
$PW\WcmSvc\GroupPolicy|fMinimizeConnections|D|3
$PW\WcmSvc\GroupPolicy|fBlockNonDomain|D|1
$PR|RegisterSpoolerRemoteRpcEndPoint|D|2
$PR|RedirectionguardPolicy|D|1
$PR|CopyFilesPolicy|D|1
$PR|DisableWebPnPDownload|D|1
$PR|DisableHTTPPrinting|D|1
$PR\RPC|RpcUseNamedPipeProtocol|D|0
$PR\RPC|RpcAuthentication|D|0
$PR\RPC|RpcProtocols|D|5
$PR\RPC|ForceKerberosForRpc|D|0
$PR\RPC|RpcTcpPort|D|0
$PR\PointAndPrint|RestrictDriverInstallationToAdministrators|D|1
$PR\PointAndPrint|UpdatePromptSettings|D|0
$PW\CurrentVersion\PushNotifications|NoCloudApplicationNotification|D|1
$PW\Explorer|HideRecommendedPersonalizedSites|D|1
$PW\Explorer|NoUseStoreOpenWith|D|1
$PW\Explorer|NoAutoplayfornonVolume|D|1
$PW\Explorer|DisableGraphRecentItems|D|1
$CV\System\Audit|ProcessCreationIncludeCmdLine_Enabled|D|1
$CV\System\CredSSP\Parameters|AllowEncryptionOracle|D|0
$PW\CredentialsDelegation|AllowProtectedCreds|D|1
$PW\DeviceGuard|EnableVirtualizationBasedSecurity|D|1
$PW\DeviceGuard|RequirePlatformSecurityFeatures|D|3
$PW\DeviceGuard|HVCIMATRequired|D|1
$DI|DenyDeviceIDs|D|1
$DI|DenyDeviceIDsRetroactive|D|1
$DI\DenyDeviceIDs|1|S|PCI\CC_0C0A
$DI|DenyDeviceClasses|D|1
$DI|DenyDeviceClassesRetroactive|D|1
$DI\DenyDeviceClasses|1|S|{d48179be-ec20-11d1-b6b8-00c04fa372a7}
$DI\DenyDeviceClasses|2|S|{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}
$DI\DenyDeviceClasses|3|S|{c06ff265-ae09-48f0-812c-16753d7cba83}
$DI\DenyDeviceClasses|4|S|{6bdd1fc1-810f-11d0-bec7-08002be2092f}
$PW\Device Metadata|PreventDeviceMetadataFromNetwork|D|1
SYSTEM\CurrentControlSet\Policies\EarlyLaunch|DriverLoadPolicy|D|3
$PW\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoBackgroundPolicy|D|0
$PW\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoGPOListChanges|D|0
$PW\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}|NoBackgroundPolicy|D|0
$PW\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}|NoGPOListChanges|D|0
$PW\System|EnableCdp|D|0
$PW\TabletPC|PreventHandwritingDataSharing|D|1
$PW\HandwritingErrorReports|PreventHandwritingErrorReports|D|1
$PW\Internet Connection Wizard|ExitOnMSICW|D|1
$CV\Explorer|NoWebServices|D|1
$CV\Explorer|NoOnlinePrintsWizard|D|1
$CV\Explorer|NoPublishingWizard|D|1
$CV\Explorer|NoAutorun|D|1
$CV\Explorer|NoDriveTypeAutoRun|D|255
$PW\Registration Wizard Control|NoRegistration|D|1
$P\SearchCompanion|DisableContentFileUpdates|D|1
$P\Messenger\Client|CEIP|D|2
$P\SQMClient\Windows|CEIPEnable|D|0
$PW\Windows Error Reporting|Disabled|D|1
$PW\Kernel DMA Protection|DeviceEnumerationPolicy|D|0
$CV\LAPS|BackupDirectory|D|2
$CV\LAPS|PwdExpirationProtectionEnabled|D|1
$CV\LAPS|ADPasswordEncryptionEnabled|D|1
$CV\LAPS|PasswordComplexity|D|4
$CV\LAPS|PasswordLength|D|15
$CV\LAPS|PasswordAgeDays|D|30
$CV\LAPS|PostAuthenticationResetDelay|D|8
$CV\LAPS|PostAuthenticationActions|D|3
$PW\System|AllowCustomSSPsAPs|D|0
SYSTEM\CurrentControlSet\Control\Lsa|RunAsPPL|D|2
$P\Control Panel\International|BlockUserInputMethodsForSignIn|D|1
$PW\System|BlockUserFromShowingAccountDetailsOnSignin|D|1
$PW\System|DontDisplayNetworkSelectionUI|D|1
$PW\System|DontEnumerateConnectedUsers|D|1
$PW\System|DisableLockScreenAppNotifications|D|1
$PW\System|BlockDomainPicturePassword|D|1
$PW\System|AllowCrossDeviceClipboard|D|0
$PW\System|UploadUserActivities|D|0
$PW\System|NoLocalPasswordResetQuestions|D|1
$PW\System|EnableSmartScreen|D|1
$PW\System|ShellSmartScreenLevel|S|Block
$P\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9|DCSettingIndex|D|0
$P\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9|ACSettingIndex|D|0
$P\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab|DCSettingIndex|D|0
$P\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab|ACSettingIndex|D|0
$TS|fAllowToGetHelp|D|0
$P\Windows NT\Rpc|EnableAuthEpResolution|D|1
$PW\ScriptedDiagnosticsProvider\Policy|DisableQueryRemoteServer|D|0
$PW\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}|ScenarioExecutionEnabled|D|0
$PW\AdvertisingInfo|DisabledByGroupPolicy|D|1
$P\W32Time\TimeProviders\NtpClient|Enabled|D|1
$PW\Appx|BlockNonAdminUserInstall|D|1
$PW\AppPrivacy|LetAppsActivateWithVoiceAboveLock|D|2
$CV\System|MSAOptional|D|1
$CV\System|BlockHostedAppAccessWinRT|D|1
$CV\System|EnableMPR|D|0
$CV\System|DisableAutomaticRestartSignOn|D|1
$P\Biometrics\FacialFeatures|EnhancedAntiSpoofing|D|1
$P\FVE|FDVDiscoveryVolumeType|S|
$P\FVE|FDVRecovery|D|1
$P\FVE|FDVManageDRA|D|1
$P\FVE|FDVRecoveryPassword|D|2
$P\FVE|FDVRecoveryKey|D|2
$P\FVE|FDVHideRecoveryPage|D|1
$P\FVE|FDVActiveDirectoryBackup|D|1
$P\FVE|FDVActiveDirectoryInfoToStore|D|1
$P\FVE|FDVRequireActiveDirectoryBackup|D|0
$P\FVE|FDVHardwareEncryption|D|0
$P\FVE|FDVPassphrase|D|0
$P\FVE|FDVAllowUserCert|D|1
$P\FVE|FDVEnforceUserCert|D|1
$P\FVE|UseEnhancedPin|D|1
$P\FVE|OSAllowSecureBootForIntegrity|D|1
$P\FVE|OSHardwareEncryption|D|0
$P\FVE|OSPassphrase|D|0
$P\FVE|UseAdvancedStartup|D|1
$P\FVE|EnableBDEWithNoTPM|D|0
$P\FVE|UseTPM|D|0
$P\FVE|UseTPMPIN|D|1
$P\FVE|UseTPMKey|D|0
$P\FVE|UseTPMKeyPIN|D|0
$P\FVE|RDVDiscoveryVolumeType|S|
$P\FVE|RDVRecovery|D|1
$P\FVE|RDVManageDRA|D|1
$P\FVE|RDVRecoveryPassword|D|0
$P\FVE|RDVRecoveryKey|D|0
$P\FVE|RDVHideRecoveryPage|D|1
$P\FVE|RDVActiveDirectoryBackup|D|0
$P\FVE|RDVActiveDirectoryInfoToStore|D|1
$P\FVE|RDVRequireActiveDirectoryBackup|D|0
$P\FVE|RDVHardwareEncryption|D|0
$P\FVE|RDVPassphrase|D|0
$P\FVE|RDVAllowUserCert|D|1
$P\FVE|RDVEnforceUserCert|D|1
$P\FVE|RDVDenyCrossOrg|D|0
$P\FVE|DisableExternalDMAUnderLock|D|1
$P\Camera|AllowCamera|D|0
$PW\CloudContent|DisableConsumerAccountStateContent|D|1
$PW\CloudContent|DisableCloudOptimizedContent|D|1
$PW\CloudContent|DisableWindowsConsumerFeatures|D|1
$PW\Connect|RequirePinForPairing|D|1
$PW\CredUI|DisablePasswordReveal|D|1
$PW\DataCollection|AllowTelemetry|D|1
$PW\DataCollection|DisableEnterpriseAuthProxy|D|1
$PW\DataCollection|DisableOneSettingsDownloads|D|1
$PW\DataCollection|DoNotShowFeedbackNotifications|D|1
$PW\DataCollection|EnableOneSettingsAuditing|D|1
$PW\DataCollection|LimitDiagnosticLogCollection|D|1
$PW\DataCollection|LimitDumpCollection|D|1
$PW\PreviewBuilds|AllowBuildPreview|D|0
$PW\AppInstaller|EnableAppInstaller|D|0
$PW\AppInstaller|EnableExperimentalFeatures|D|0
$PW\AppInstaller|EnableHashOverride|D|0
$PW\AppInstaller|EnableMSAppInstallerProtocol|D|0
$PW\EventLog\Application|MaxSize|D|32768
$PW\EventLog\Security|MaxSize|D|196608
$PW\EventLog\Setup|MaxSize|D|32768
$PW\EventLog\System|MaxSize|D|32768
$PW\LocationAndSensors|DisableLocation|D|1
$PW\Messaging|AllowMessageSync|D|0
$P\MicrosoftAccount|DisableUserAuth|D|1
$WD\Windows Defender Exploit Guard\ASR|ExploitGuard_ASR_Rules|D|1
$WD\Windows Defender Exploit Guard\ASR\Rules|BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|D4F940AB-401B-4EFC-AADC-AD5F3C50688A|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|3B576869-A4EC-4529-8536-B80A7769E899|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|D3E037E1-3EB8-44C8-A917-57927947596D|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|5BEB7EFE-FD9A-4556-801D-275E5FFC04CC|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|26190899-1602-49E8-8B27-EB1D0A1CE869|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2|S|1
$WD\Windows Defender Exploit Guard\ASR\Rules|B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4|S|1
$WD\Windows Defender Exploit Guard\Network Protection|EnableNetworkProtection|D|1
$WD\MpEngine|EnableFileHashComputation|D|1
$WD\Reporting|DisableGenericRePorts|D|1
$WD\Scan|DisableRemovableDriveScanning|D|0
$WD\Scan|DisableEmailScanning|D|0
$WD|PUAProtection|D|1
$P\Windows Defender Security Center\App and Browser protection|DisallowExploitProtectionOverride|D|1
$P\AppHVSI|AuditApplicationGuard|D|1
$P\AppHVSI|AllowCameraMicrophoneRedirection|D|0
$P\AppHVSI|AllowPersistence|D|0
$P\AppHVSI|SaveFilesToHost|D|0
$P\AppHVSI|AppHVSIClipboardSettings|D|1
$P\AppHVSI|AllowAppHVSI_ProviderSet|D|1
$PW\Windows Feeds|EnableFeeds|D|0
$PW\OneDrive|DisableFileSyncNGSC|D|1
$P\PushToInstall|DisablePushToInstall|D|1
$TS\Client|DisableCloudClipboardIntegration|D|1
$TS|DisablePasswordSaving|D|1
$TS|EnableUiaRedirection|D|0
$TS|fDisableCcm|D|1
$TS|fDisableLocationRedir|D|1
$TS|fDisableLPT|D|1
$TS|fDisablePNPRedir|D|1
$TS|fDisableWebAuthn|D|1
$TS|fPromptForPassword|D|1
$TS|fEncryptRPCTraffic|D|1
$TS|SecurityLayer|D|2
$P\Internet Explorer\Feeds|DisableEnclosureDownload|D|1
$PW\Windows Search|AllowCloudSearch|D|0
$PW\Windows Search|AllowCortana|D|0
$PW\Windows Search|AllowCortanaAboveLock|D|0
$PW\Windows Search|AllowSearchToUseLocation|D|0
$PW\Windows Search|EnableDynamicContentInWSB|D|0
$P\Windows NT\CurrentVersion\Software Protection Platform|NoGenTicket|D|1
$P\WindowsStore|RequirePrivateStoreOnly|D|1
$P\WindowsStore|DisableOSUpgrade|D|1
$P\WindowsStore|RemoveWindowsStore|D|1
$P\Dsh|AllowNewsAndInterests|D|0
$PW\WTDS\Components|CaptureThreatWindow|D|1
$PW\WTDS\Components|NotifyMalicious|D|1
$PW\WTDS\Components|NotifyPasswordReuse|D|1
$PW\WTDS\Components|NotifyUnsafeApp|D|1
$PW\WTDS\Components|ServiceEnabled|D|1
$PW\GameDVR|AllowGameDVR|D|0
$P\WindowsInkWorkspace|AllowSuggestedAppsInWindowsInkWorkspace|D|0
$P\WindowsInkWorkspace|AllowWindowsInkWorkspace|D|1
$PW\PowerShell\Transcription|EnableTranscripting|D|1
$PW\WinRM\Client|AllowDigest|D|0
$PW\WinRM\Service|DisableRunAs|D|1
$PW\WinRM\Service\WinRS|AllowRemoteShellAccess|D|0
$PW\Sandbox|AllowClipboardRedirection|D|0
$PW\Sandbox|AllowNetworking|D|0
$PW\WindowsUpdate|SetDisablePauseUXAccess|D|1
$PW\WindowsUpdate|DeferFeatureUpdates|D|1
$PW\WindowsUpdate|DeferFeatureUpdatesPeriodInDays|D|180
"@
# Entries above that look odd but are deliberate:
#  - Wow6432Node\...: the Wazuh agent is a 32-bit process and reads the redirected view.
#  - FirewallRules CIS-SSH-In / CIS-RDP-In: the Public profile ignores local rules (26133), so
#    if the client ever comes up as Public, these keep it reachable.
#  - FDV/RDVDiscoveryVolumeType empty: CIS "Disabled" = no discovery volume for older Windows.

$gpo = Get-CisGpo 'CIS - Workstations'
Write-RegistryPol $gpo $Reg
Write-SecTemplate $gpo $Inf
Write-AuditCsv $gpo $Audit
Publish-Gpo $gpo "$ExtRegistry$ExtSecurity$ExtAudit"
Set-FirstLink $gpo "OU=Workstations,$($domain.DistinguishedName)"
# Clients pick it up at their next background refresh (90-120 min), gpupdate or reboot.
