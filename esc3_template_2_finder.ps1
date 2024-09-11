<#
.SYNOPSIS
Find certificate templates that can be used in the second phase of the ESC3 attack.

.PARAMETER Domain
Certification authority domain.

.PARAMETER ForeignDomain
If the computer is not domain joined or is in a different forest than the target domain, the SIDs mapping will be made through an LDAP query.
#>

Param(
	[Parameter(Position = 0, Mandatory = $true)]
	[string] $Domain,
	
	[Parameter(Position = 1, Mandatory = $false)]
	[switch] $ForeignDomain
)

# https=//github.com/ly4k/Certipy/blob/2780d5361121dd4ec79da3f64cfb1984c4f779c6/certipy/lib/constants.py#L143
$oids = @{ "2.5.29.37.0" = "Any Purpose"
"1.3.6.1.5.5.7.3.2" = "Client Authentication"
"1.3.6.1.5.2.3.4" = "PKINIT Client Authentication"
"1.3.6.1.4.1.311.20.2.2" = "Smart Card Logon"
"1.3.6.1.4.1.311.20.2.1" = "Certificate Request Agent"
"1.3.6.1.5.5.7.3.3" = "Code Signing"
"1.3.6.1.4.1.311.10.3.4" = "Encrypting File System"
"1.3.6.1.4.1.311.10.3.4.1" = "File Recovery"
"1.3.6.1.4.1.311.10.3.13" = "Lifetime Signing"
"1.3.6.1.4.1.311.76.6.1" = "Windows Update"
"1.3.6.1.4.1.311.10.3.11" = "Key Recovery"
"1.3.6.1.4.1.311.10.3.25" = "Windows Third Party Application Component"
"1.3.6.1.4.1.311.21.6" = "Key Recovery Agent"
"1.3.6.1.4.1.311.10.3.6" = "Windows System Component Verification"
"1.3.6.1.4.1.311.61.4.1" = "Early Launch Antimalware Drive"
"1.3.6.1.4.1.311.10.3.23" = "Windows TCB Component"
"1.3.6.1.4.1.311.61.1.1" = "Kernel Mode Code Signing"
"1.3.6.1.4.1.311.10.3.26" = "Windows Software Extension Verification"
"2.23.133.8.3" = "Attestation Identity Key Certificate"
"1.3.6.1.4.1.311.76.3.1" = "Windows Store"
"1.3.6.1.4.1.311.10.6.1" = "Key Pack Licenses"
"1.3.6.1.5.2.3.5" = "KDC Authentication"
"1.3.6.1.5.5.7.3.7" = "IP security use"
"1.3.6.1.4.1.311.10.3.8" = "Embedded Windows System Component Verification"
"1.3.6.1.4.1.311.10.3.20" = "Windows Kits Component"
"1.3.6.1.5.5.7.3.6" = "IP security tunnel termination"
"1.3.6.1.4.1.311.10.3.5" = "Windows Hardware Driver Verification"
"1.3.6.1.5.5.8.2.2" = "IP security IKE intermediate"
"1.3.6.1.4.1.311.10.3.39" = "Windows Hardware Driver Extended Verification"
"1.3.6.1.4.1.311.10.6.2" = "License Server Verification"
"1.3.6.1.4.1.311.10.3.5.1" = "Windows Hardware Driver Attested Verification"
"1.3.6.1.4.1.311.76.5.1" = "Dynamic Code Generato"
"1.3.6.1.5.5.7.3.8" = "Time Stamping"
"1.3.6.1.4.1.311.2.6.1" = "SpcRelaxedPEMarkerCheck"
"2.23.133.8.1" = "Endorsement Key Certificate"
"1.3.6.1.4.1.311.2.6.2" = "SpcEncryptedDigestRetryCount"
"1.3.6.1.5.5.7.3.1" = "Server Authentication"
"1.3.6.1.4.1.311.61.5.1" = "HAL Extension"
"1.3.6.1.5.5.7.3.4" = "Secure Email"
"1.3.6.1.5.5.7.3.5" = "IP security end system"
"1.3.6.1.4.1.311.10.3.9" = "Root List Signe"
"1.3.6.1.4.1.311.10.3.30" = "Disallowed List"
"1.3.6.1.4.1.311.10.3.19" = "Revoked List Signe"
"1.3.6.1.4.1.311.10.3.21" = "Windows RT Verification"
"1.3.6.1.4.1.311.10.3.10" = "Qualified Subordination"
"1.3.6.1.4.1.311.10.3.12" = "Document Signing"
"1.3.6.1.4.1.311.10.3.24" = "Protected Process Verification"
"1.3.6.1.4.1.311.80.1" = "Document Encryption"
"1.3.6.1.4.1.311.10.3.22" = "Protected Process Light Verification"
"1.3.6.1.4.1.311.21.19" = "Directory Service Email Replication"
"1.3.6.1.4.1.311.21.5" = "Private Key Archival"
"1.3.6.1.4.1.311.10.5.1" = "Digital Rights"
"1.3.6.1.4.1.311.10.3.27" = "Preview Build Signing"
"2.23.133.8.2" = "Platform Certificate"
"1.3.6.1.4.1.311.20.1" = "CTL Usage"
"1.3.6.1.5.5.7.3.9" = "OCSP Signing"
"1.3.6.1.4.1.311.10.3.1" = "Microsoft Trust List Signing"
"1.3.6.1.4.1.311.10.3.2" = "Microsoft Time Stamping"
"1.3.6.1.4.1.311.76.8.1" = "Microsoft Publishe"
"1.3.6.1.4.1.311.64.1.1" = "Server Trust"
"1.3.6.1.4.1.311.10.3.7" = "OEM Windows System Component Verification" }

# https=//learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
$enrollment_flags = @{ "0x00000001" = "CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS"
"0x00000002" = "CT_FLAG_PEND_ALL_REQUESTS"
"0x00000004" = "CT_FLAG_PUBLISH_TO_KRA_CONTAINER"
"0x00000008" = "CT_FLAG_PUBLISH_TO_DS"
"0x00000010" = "CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"
"0x00000020" = "CT_FLAG_AUTO_ENROLLMENT"
"0x00000040" = "CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"
"0x00000100" = "CT_FLAG_USER_INTERACTION_REQUIRED"
"0x00000400" = "CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"
"0x00000800" = "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF"
"0x00001000" = "CT_FLAG_ADD_OCSP_NOCHECK"
"0x00002000" = "CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"
"0x00004000" = "CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS"
"0x00008000" = "CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"
"0x00010000" = "CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"
"0x00020000" = "CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST"
"0x00040000" = "CT_FLAG_SKIP_AUTO_RENEWAL"
"0x00080000" = "CT_FLAG_NO_SECURITY_EXTENSION" }

function parse_template_data($template){
	$ekus = @()
	$policies = @()
	$flags = @()

	foreach($eku in $template.pKIExtendedKeyUsage){
		$ekus += $oids[$eku]
	}
	$template.pKIExtendedKeyUsage = $ekus

	foreach($pol in $template."msPKI-RA-Application-Policies"){
		$policies += $oids[$pol]
	}
	$template."msPKI-RA-Application-Policies" = $policies

	foreach($flag in $enrollment_flags.Keys){
		if(($template."msPKI-Enrollment-Flag"[0] -band $flag) -eq $flag){
			$flags += $enrollment_flags[$flag]
		}
	}
	$template."msPKI-Enrollment-Flag" = $flags
	
	return $template
}

function parse_sids($sids, $domain, $dc){
	$search_filter = "(|(objectSid=" + $($sids.Keys -join ")(objectSid=") + "))"
	$ldapPath = "LDAP://$dc"
	$ldapPath
	$search_filter
	
	$searcher = [ADSISearcher]($search_filter)
	$searcher.SearchRoot = [ADSI]$ldapPath
	$result = $searcher.FindAll()
	
	foreach($p in $result.Properties){
		$sid = $(New-Object System.Security.Principal.SecurityIdentifier($p.objectsid[0], 0)).Value
		$sids[$sid] = $domain + "\" + $p.samaccountname
	}
}

Get-Date -Format "dd/MM/yyyy HH:mm K"
$dc = "DC=" + $($Domain.split(".") -join ",DC=")
$es_search_base = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$dc"
$ct_search_base = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$dc"
$ct_search_base
$es_search_base
Write-Host
$es = ([ADSI]$es_search_base)
$ct = ([ADSI]$ct_search_base)

# Any Purpose, Client Authentication, PKINIT Client Authentication, Smart Card Logon
$auth_oids = @("2.5.29.37.0", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2") -Join "" 

# Certificate Request Agent
$agent_oid = "1.3.6.1.4.1.311.20.2.1" 

# Manager Approval
$CT_FLAG_PEND_ALL_REQUESTS = 0x2 

# https://github.com/ly4k/Certipy/blob/main/certipy/lib/constants.py#L283
$enroll_right = "0e10c968-78fb-11d2-90d4-00c04f79dc55"

$t2_free = $ct.Children | where { `
(($_."msPKI-Template-Schema-Version" -eq 1 -and $_."msPKI-RA-Signature"[0] -eq 0) `
-or ($_."msPKI-Template-Schema-Version" -ge 2 -and $_."msPKI-RA-Signature"[0] -eq 1 -and $agent_oid -in $_."msPKI-RA-Application-Policies")) `
-and ($_.pKIExtendedKeyUsage.Count -eq 0 -or $auth_oids -match $($_.pKIExtendedKeyUsage -join "|")) `
-and ($_."msPKI-Enrollment-Flag"[0] -band $CT_FLAG_PEND_ALL_REQUESTS) -ne $CT_FLAG_PEND_ALL_REQUESTS }

$oldFormatLimit = $global:FormatEnumerationLimit
$global:FormatEnumerationLimit = -1
$all_sids = @{}
$enabled_templates = @()

foreach($t in $t2_free){
	$cas = @()
	$enabled = $false
	
	foreach($ca in $es.Children){
		if($t.Name -in $ca.CertificateTemplates){
			$cas += $ca.Name
			$enabled = $true
		}
	}
	
	if($enabled){
		$t = parse_template_data $t
		$enroll = $($t.ObjectSecurity.Access | ?{ $_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and $_.ObjectType -eq $enroll_right }).IdentityReference.Value
		$t | Add-Member -MemberType NoteProperty -Name "Enrollment Rights" -Value $enroll -Force
		$t | Add-Member -MemberType NoteProperty -Name "Certification Authorities" -Value $cas -Force
		
		if($ForeignDomain){
			foreach($sid in $t."Enrollment Rights"){
				if($sid -like "S-*-*-*"){
					$all_sids[$sid] = "not_parsed"
				}
			}
		}
		$enabled_templates += $t
	}
}

if($ForeignDomain){
	parse_sids $all_sids $Domain $dc

	foreach($t in $enabled_templates){
		$enrollers = @()
		
		foreach($sid in $t."Enrollment Rights"){
			if($sid -in $all_sids.Keys){
				$enrollers += $all_sids[$sid]
			}
			else{
				$enrollers += $sid
			}
		}
		$t."Enrollment Rights" = $enrollers
	}
}
$enabled_templates | select Name, msPKI-Template-Schema-Version, pKIExtendedKeyUsage, msPKI-RA-Signature, msPKI-RA-Application-Policies, msPKI-Enrollment-Flag, "Certification Authorities", "Enrollment Rights" | fl
$global:FormatEnumerationLimit = $oldFormatLimit
