<#
CIS Microsoft Windows Server 2025 Benchmark v1.0.0 for the lab DC (cy-dc-lab-01, isu.int):
the checks Wazuh SCA reported as failed on 2026-10-13, as two GPOs.

  CIS - Domain Account Policy   linked at the domain root  (password + lockout policy)
  CIS - Domain Controllers      linked at OU=Domain Controllers (everything else)

Run on the DC as Domain Admin, next to CisGpo.ps1. Re-running is safe: it rewrites both GPOs.
Check the result without waiting for the Wazuh manager: gen_verifier.py next to this file
turns the agent's SCA policy (C:\Program Files (x86)\ossec-agent\ruleset\sca\cis_win2025.yml)
into a read-only verify_sca.ps1 that evaluates the checks the way the agent does
(wazuh-failed-2026-10-13.txt = the IDs this script covers). After applying: 282 of 294 pass.

Unlinking the GPOs does not undo everything: values outside the Policies keys (Lsa, Tcpip,
NetBT, LanmanServer, Spooler start type, ...) stay set ("tattooed") until changed back.

Checks that stay failed, and why (not applied because it would break the lab, or Wazuh can't see it):
  36508        Guest disabled         applied, but Wazuh queries local accounts and a DC has none
  36510        rename Administrator   SSH key login and every lab script use "administrator"
  36645        SMB1 client driver     mrxsmb10 isn't installed on Server 2025, nothing to disable
  36689        disable IPv6           unsupported by Microsoft on domain controllers
  36713, 36715 HVCI / CredGuard        HVCI with UEFI lock is one-way and blocks incompatible drivers
                                      the moment VBS can start; CredGuard is MS only.
                                      (36711/12/14/17 are set: inert on this VM, VBS can't start
                                      without virtualisation extensions, but harmless if it ever can)
  36750        LSASS PPL + UEFI lock  set to 2 (PPL without UEFI lock) instead - the check stays failed
  36769        restrict unauth. RPC   "MS only", breaks RPC on a DC
  36772        SAM change-pw "block"  "MS only", same value as 36771 which a DC needs (strong only)
  36800, 36804 AppInstaller           set, but Wazuh can't pass them: its rule lacks a space in
                                      "->EnableAppInstaller" and so looks for a value named "0";
                                      not worked around with a dummy value

Changed on purpose:
  36625        Detailed File Share    Success only, not Success+Failure: deelpe-winagent reads every
                                      5145 without looking at success/failure, so denied accesses
                                      (its own lockdown ACLs) would count as reads. File System and
                                      Detailed File Share Success are what audit.rs keeps on.
  36741-36748  LAPS                   BackupDirectory=1 (Entra) passes the check but does nothing on
                                      a DC. 2 (AD) would rotate the DSRM password into AD - unreadable
                                      exactly when DSRM is needed on this single-DC domain.
#>
param([switch]$NoGpupdate)
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\CisGpo.ps1"

# --- Account policy (1.1, 1.2) and the Guest account: on a DC [System Access] is only read
# from GPOs linked at the domain root.
$AccountInf = @'
[System Access]
EnableGuestAccount = 0
NewGuestName = "isu-visitor"
MinimumPasswordLength = 14
PasswordHistorySize = 24
MaximumPasswordAge = 365
LockoutBadCount = 5
LockoutDuration = 15
ResetLockoutCount = 15
'@

# --- Security template of the DC GPO. Security options live here (not in Registry.pol) because
# the Default Domain Controllers Policy sets some of them, e.g. LDAPServerIntegrity=1, and only
# the security CSE resolves that by link order.
$DcInf = @'
[Service General Setting]
"Spooler",4,""
[Registry Values]
MACHINE\System\CurrentControlSet\Control\SAM\RelaxMinimumPasswordLengthLimits=4,1
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding=4,2
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"ISU lab - authorized use only"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=1,"This system is for authorized ISU lab use only. Activity is logged and monitored."
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"4"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,14
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"1"
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SMBServerNameHardeningLevel=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic=4,2
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain=4,7
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483640
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
'@

# --- Advanced audit policy: CIS 17.x merged with what the DC already audited, so nothing that
# was on goes off. 1 = Success, 2 = Failure, 3 = Success and Failure.
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
Network Policy Server|{0CCE9243-69AE-11D9-BED3-505054503030}|3
Group Membership|{0CCE9249-69AE-11D9-BED3-505054503030}|1
File System|{0CCE921D-69AE-11D9-BED3-505054503030}|1
File Share|{0CCE9224-69AE-11D9-BED3-505054503030}|3
Other Object Access Events|{0CCE9227-69AE-11D9-BED3-505054503030}|3
Detailed File Share|{0CCE9244-69AE-11D9-BED3-505054503030}|1
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
Computer Account Management|{0CCE9236-69AE-11D9-BED3-505054503030}|1
Security Group Management|{0CCE9237-69AE-11D9-BED3-505054503030}|1
Distribution Group Management|{0CCE9238-69AE-11D9-BED3-505054503030}|1
Application Group Management|{0CCE9239-69AE-11D9-BED3-505054503030}|3
Other Account Management Events|{0CCE923A-69AE-11D9-BED3-505054503030}|1
Directory Service Access|{0CCE923B-69AE-11D9-BED3-505054503030}|3
Directory Service Changes|{0CCE923C-69AE-11D9-BED3-505054503030}|1
Credential Validation|{0CCE923F-69AE-11D9-BED3-505054503030}|3
Kerberos Service Ticket Operations|{0CCE9240-69AE-11D9-BED3-505054503030}|3
Kerberos Authentication Service|{0CCE9242-69AE-11D9-BED3-505054503030}|3
'@

# --- Administrative templates and MSS values: Registry.pol. key | value | D(word) or S(tring) | data
$P  = 'SOFTWARE\Policies\Microsoft'
$PW = 'SOFTWARE\Policies\Microsoft\Windows'
$CV = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
$TS = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$WD = 'SOFTWARE\Policies\Microsoft\Windows Defender'
$PR = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$Reg = @"
$P\WindowsFirewall\DomainProfile|EnableFirewall|D|1
$P\WindowsFirewall\DomainProfile|DefaultInboundAction|D|1
$P\WindowsFirewall\DomainProfile|DisableNotifications|D|1
$P\WindowsFirewall\DomainProfile\Logging|LogFilePath|S|%SystemRoot%\System32\logfiles\firewall\domainfw.log
$P\WindowsFirewall\DomainProfile\Logging|LogFileSize|D|16384
$P\WindowsFirewall\DomainProfile\Logging|LogDroppedPackets|D|1
$P\WindowsFirewall\DomainProfile\Logging|LogSuccessfulConnections|D|1
$P\WindowsFirewall\PrivateProfile|EnableFirewall|D|1
$P\WindowsFirewall\PrivateProfile|DefaultInboundAction|D|1
$P\WindowsFirewall\PrivateProfile|DisableNotifications|D|1
$P\WindowsFirewall\PrivateProfile\Logging|LogFilePath|S|%SystemRoot%\System32\logfiles\firewall\privatefw.log
$P\WindowsFirewall\PrivateProfile\Logging|LogFileSize|D|16384
$P\WindowsFirewall\PrivateProfile\Logging|LogDroppedPackets|D|1
$P\WindowsFirewall\PrivateProfile\Logging|LogSuccessfulConnections|D|1
$P\WindowsFirewall\PublicProfile|EnableFirewall|D|1
$P\WindowsFirewall\PublicProfile|DefaultInboundAction|D|1
$P\WindowsFirewall\PublicProfile|DisableNotifications|D|1
$P\WindowsFirewall\PublicProfile|AllowLocalPolicyMerge|D|0
$P\WindowsFirewall\PublicProfile|AllowLocalIPsecPolicyMerge|D|0
$P\WindowsFirewall\PublicProfile\Logging|LogFilePath|S|%SystemRoot%\System32\logfiles\firewall\publicfw.log
$P\WindowsFirewall\PublicProfile\Logging|LogFileSize|D|16384
$P\WindowsFirewall\PublicProfile\Logging|LogDroppedPackets|D|1
$P\WindowsFirewall\PublicProfile\Logging|LogSuccessfulConnections|D|1
$P\WindowsFirewall\FirewallRules|CIS-SSH-In|S|v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=22|Name=CIS keep SSH reachable|
$P\WindowsFirewall\FirewallRules|CIS-RDP-In|S|v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=CIS keep RDP reachable|
$PW\Personalization|NoLockScreenCamera|D|1
$PW\Personalization|NoLockScreenSlideshow|D|1
$P\InputPersonalization|AllowInputPersonalization|D|0
$CV\Explorer|AllowOnlineTips|D|0
SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|SMB1|D|0
SOFTWARE\Microsoft\Cryptography\Wintrust\Config|EnableCertPaddingCheck|D|1
SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config|EnableCertPaddingCheck|D|1
SYSTEM\CurrentControlSet\Services\NetBT\Parameters|NodeType|D|2
SYSTEM\CurrentControlSet\Services\NetBT\Parameters|NoNameReleaseOnDemand|D|1
SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|DisableIPSourceRouting|D|2
SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters|TcpMaxDataRetransmissions|D|3
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|DisableIPSourceRouting|D|2
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|EnableICMPRedirect|D|0
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|KeepAliveTime|D|300000
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|PerformRouterDiscovery|D|0
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters|TcpMaxDataRetransmissions|D|3
SYSTEM\CurrentControlSet\Control\Session Manager|SafeDllSearchMode|D|1
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|ScreenSaverGracePeriod|S|5
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon|ScreenSaverGracePeriod|S|5
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon|CachedLogonsCount|S|4
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon|PasswordExpiryWarning|D|14
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon|ScRemoveOption|S|1
SYSTEM\CurrentControlSet\Services\Eventlog\Security|WarningLevel|D|90
$P\Windows NT\DNSClient|EnableMDNS|D|0
$P\Windows NT\DNSClient|DisableIPv6DefaultDnsServers|D|1
$P\Windows NT\DNSClient|EnableMulticast|D|0
$PW\System|EnableFontProviders|D|0
$PW\LanmanServer|AuditClientDoesNotSupportEncryption|D|1
$PW\LanmanServer|AuditClientDoesNotSupportSigning|D|1
$PW\LanmanServer|AuditInsecureGuestLogon|D|1
$PW\LanmanServer|MinSmb2Dialect|D|785
$PW\LanmanServer|InvalidAuthenticationDelayTimeInMs|D|2000
$PW\LanmanServer|EnableAuthRateLimiter|D|1
$PW\LanmanWorkstation|AuditInsecureGuestLogon|D|1
$PW\LanmanWorkstation|AuditServerDoesNotSupportEncryption|D|1
$PW\LanmanWorkstation|AuditServerDoesNotSupportSigning|D|1
$PW\LanmanWorkstation|AllowInsecureGuestAuth|D|0
$PW\LanmanWorkstation|MinSmb2Dialect|D|785
$PW\LanmanWorkstation|RequireEncryption|D|1
$PW\Bowser|EnableMailslots|D|0
$PW\NetworkProvider|EnableMailslots|D|0
$PW\NetworkProvider\HardenedPaths|\\*\NETLOGON|S|RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1
$PW\NetworkProvider\HardenedPaths|\\*\SYSVOL|S|RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1
$P\Peernet|Disabled|D|1
$PW\Network Connections|NC_AllowNetBridge_NLA|D|0
$PW\Network Connections|NC_ShowSharedAccessUI|D|0
$PW\Network Connections|NC_StdDomainUserSetLocation|D|1
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
$PR\WPP|WindowsProtectedPrintGroupPolicyState|D|1
$PR\PointAndPrint|RestrictDriverInstallationToAdministrators|D|1
SYSTEM\CurrentControlSet\Control\Print|RpcAuthnLevelPrivacyEnabled|D|1
$PW\CurrentVersion\PushNotifications|NoCloudApplicationNotification|D|1
$CV\System\Audit|ProcessCreationIncludeCmdLine_Enabled|D|1
$CV\System\CredSSP\Parameters|AllowEncryptionOracle|D|0
$PW\CredentialsDelegation|AllowProtectedCreds|D|1
$PW\DeviceGuard|EnableVirtualizationBasedSecurity|D|1
$PW\DeviceGuard|RequirePlatformSecurityFeatures|D|3
$PW\DeviceGuard|HVCIMATRequired|D|1
$PW\DeviceGuard|ConfigureSystemGuardLaunch|D|1
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
$P\PCHealth\ErrorReporting|DoReport|D|0
$CV\System\kerberos\parameters|DevicePKInitBehavior|D|0
$CV\System\kerberos\parameters|DevicePKInitEnabled|D|1
$PW\Kernel DMA Protection|DeviceEnumerationPolicy|D|0
$CV\LAPS|BackupDirectory|D|1
$CV\LAPS|PasswordLength|D|15
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
$PW\System|EnableSmartScreen|D|1
$PW\System|ShellSmartScreenLevel|S|Block
$P\Netlogon\Parameters|BlockNetbiosDiscovery|D|1
$P\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9|DCSettingIndex|D|0
$P\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9|ACSettingIndex|D|0
$P\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|DCSettingIndex|D|1
$P\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|ACSettingIndex|D|1
$P\Windows NT\Rpc|EnableAuthEpResolution|D|1
$CV\System\SAM|SamNGCKeyROCAValidation|D|1
$CV\System\SAM|SamrChangeUserPasswordApiPolicy|D|2
$PW\ScriptedDiagnosticsProvider\Policy|DisableQueryRemoteServer|D|0
$PW\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}|ScenarioExecutionEnabled|D|0
$PW\AdvertisingInfo|DisabledByGroupPolicy|D|1
$P\W32Time\TimeProviders\NtpClient|Enabled|D|1
$PW\Appx|DisablePerUserUnsignedPackagesByDefault|D|1
$CV\System|MSAOptional|D|1
$CV\System|EnableMPR|D|0
$PW\Explorer|NoAutoplayfornonVolume|D|1
$PW\Explorer|DisableMotWOnInsecurePathCopy|D|0
$P\Biometrics\FacialFeatures|EnhancedAntiSpoofing|D|1
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
$PW\AppInstaller|EnableLocalArchiveMalwareScanOverride|D|0
$PW\AppInstaller|EnableMSAppInstallerProtocol|D|0
$PW\AppInstaller|EnableBypassCertificatePinningForMicrosoftStore|D|0
$PW\AppInstaller|EnableWindowsPackageManagerCommandLineInterfaces|D|0
$PW\EventLog\Application|MaxSize|D|32768
$PW\EventLog\Security|MaxSize|D|196608
$PW\EventLog\Setup|MaxSize|D|32768
$PW\EventLog\System|MaxSize|D|32768
$PW\LocationAndSensors|DisableLocation|D|1
$PW\Messaging|AllowMessageSync|D|0
$P\MicrosoftAccount|DisableUserAuth|D|1
$WD\Features|PassiveRemediation|D|1
$P\MicrosoftAccount|PassiveRemediation|D|1
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
$WD\NIS|EnableConvertWarnToBlock|D|1
$WD\Real-Time Protection|OobeEnableRtpAndSigUpdate|D|1
$WD\Remediation\Behavioral Network Blocks\Brute Force Protection|BruteForceProtectionAggressiveness|D|1
$WD\Remediation\Behavioral Network Blocks\Brute Force Protection|BruteForceProtectionConfiguredState|D|2
$WD\Remediation\Behavioral Network Blocks\Remote Encryption Protection|RemoteEncryptionProtectionAggressiveness|D|1
$WD\Remediation\Behavioral Network Blocks\Remote Encryption Protection|RemoteEncryptionProtectionConfiguredState|D|2
$WD\Reporting|DisableGenericRePorts|D|1
$WD\Scan|QuickScanIncludeExclusions|D|1
$WD\Scan|DisablePackedExeScanning|D|0
$WD\Scan|DisableRemovableDriveScanning|D|0
$WD\Scan|DaysUntilAggressiveCatchupQuickScan|D|7
$WD\Scan|DisableEmailScanning|D|0
$WD|PUAProtection|D|1
$WD|HideExclusionsFromLocalUsers|D|1
$P\Windows Defender Security Center\App and Browser protection|DisallowExploitProtectionOverride|D|1
$PW\OneDrive|DisableFileSyncNGSC|D|1
$P\PushToInstall|DisablePushToInstall|D|1
$TS|fAllowToGetHelp|D|0
$TS|DisablePasswordSaving|D|1
$TS|fSingleSessionPerUser|D|1
$TS|EnableUiaRedirection|D|0
$TS|fDisableCcm|D|1
$TS|fDisableCdm|D|1
$TS|fDisableLocationRedir|D|1
$TS|fDisableLPT|D|1
$TS|fDisablePNPRedir|D|1
$TS|fDisableWebAuthn|D|1
$TS|SCClipLevel|D|0
$TS|fPromptForPassword|D|1
$TS|fEncryptRPCTraffic|D|1
$TS|SecurityLayer|D|2
$TS|UserAuthentication|D|1
$TS|MinEncryptionLevel|D|3
$TS|MaxIdleTime|D|900000
$TS|MaxDisconnectionTime|D|60000
$TS|DeleteTempDirsOnExit|D|1
$TS|PerSessionTempDir|D|1
$P\Internet Explorer\Feeds|DisableEnclosureDownload|D|1
$P\Internet Explorer\Feeds|AllowBasicAuthInClear|D|0
$PW\Windows Search|AllowCloudSearch|D|0
$PW\Windows Search|EnableDynamicContentInWSB|D|0
$P\Windows NT\CurrentVersion\Software Protection Platform|NoGenTicket|D|1
$P\WindowsInkWorkspace|AllowSuggestedAppsInWindowsInkWorkspace|D|0
$P\WindowsInkWorkspace|AllowWindowsInkWorkspace|D|1
$PW\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging|D|1
$PW\PowerShell\Transcription|EnableTranscripting|D|1
$PW\WinRM\Client|AllowDigest|D|0
$PW\WinRM\Service|DisableRunAs|D|1
$PW\WinRM\Service\WinRS|AllowRemoteShellAccess|D|0
$PW\WindowsUpdate\AU|ScheduledInstallDay|D|0
$PW\WindowsUpdate|DeferFeatureUpdates|D|1
$PW\WindowsUpdate|DeferFeatureUpdatesPeriodInDays|D|180
$PW\WindowsUpdate|DeferQualityUpdates|D|1
$PW\WindowsUpdate|DeferQualityUpdatesPeriodInDays|D|0
"@
# Entries above that look odd but are deliberate:
#  - MicrosoftAccount\PassiveRemediation: Wazuh's check 36822 looks there (bug in the SCA file);
#    the real "EDR in block mode" switch is Windows Defender\Features\PassiveRemediation.
#  - Wow6432Node\...\Winlogon: the Wazuh agent is a 32-bit process and reads the redirected
#    view; Windows itself reads the 64-bit values set in the security template.
#  - FirewallRules CIS-SSH-In / CIS-RDP-In: the Public profile ignores local rules (36600), so if
#    the DC ever comes up as Public, these keep SSH and RDP open to repair it.

# Account policy GPO
$acct = Get-CisGpo 'CIS - Domain Account Policy'
Write-SecTemplate $acct $AccountInf
Publish-Gpo $acct $ExtSecurity

# DC GPO
$dc = Get-CisGpo 'CIS - Domain Controllers'
Write-RegistryPol $dc $Reg
Write-SecTemplate $dc $DcInf
Write-AuditCsv $dc $Audit
Publish-Gpo $dc "$ExtRegistry$ExtSecurity$ExtAudit"

Set-FirstLink $acct $domain.DistinguishedName
Set-FirstLink $dc $domain.DomainControllersContainer

if (-not $NoGpupdate) {
    gpupdate /force /target:computer | Out-Host
    # The security CSE only sets Start=4; the running spooler stays up until it is stopped.
    Stop-Service Spooler -Force -ErrorAction SilentlyContinue
}
