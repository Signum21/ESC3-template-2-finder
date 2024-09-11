from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, SASL, KERBEROS
from ldap3.protocol.microsoft import security_descriptor_control
from certipy.lib.security import CertifcateSecurity
from certipy.lib.constants import OID_TO_STR_MAP
from gssapi import Credentials
from datetime import datetime
import argparse

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
enrollment_flags = { 
    "0x00000001" : "CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS",
    "0x00000002" : "CT_FLAG_PEND_ALL_REQUESTS",
    "0x00000004" : "CT_FLAG_PUBLISH_TO_KRA_CONTAINER",
    "0x00000008" : "CT_FLAG_PUBLISH_TO_DS",
    "0x00000010" : "CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    "0x00000020" : "CT_FLAG_AUTO_ENROLLMENT",
    "0x00000040" : "CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    "0x00000100" : "CT_FLAG_USER_INTERACTION_REQUIRED",
    "0x00000400" : "CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    "0x00000800" : "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF",
    "0x00001000" : "CT_FLAG_ADD_OCSP_NOCHECK",
    "0x00002000" : "CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    "0x00004000" : "CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS",
    "0x00008000" : "CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    "0x00010000" : "CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
    "0x00020000" : "CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST",
    "0x00040000" : "CT_FLAG_SKIP_AUTO_RENEWAL",
    "0x00080000" : "CT_FLAG_NO_SECURITY_EXTENSION" 
}


def parse_template_data(template):
    ekus = []
    policies = []
    enroll_flags = []
    
    for eku in template["pKIExtendedKeyUsage"]:
        ekus.append(OID_TO_STR_MAP[eku])
    template["pKIExtendedKeyUsage"] = ekus
    
    for pol in template["msPKI-RA-Application-Policies"]:
        policies.append(OID_TO_STR_MAP[pol])
    template["msPKI-RA-Application-Policies"] = policies
    
    for flag in enrollment_flags:
        if (int(flag, 16) & template["msPKI-Enrollment-Flag"]) == int(flag, 16):
            enroll_flags.append(enrollment_flags[flag])
    template["msPKI-Enrollment-Flag"] = enroll_flags
    
    return template


def parse_template(c, template, all_cas, domains, sids):
    # Any Purpose, Client Authentication, PKINIT Client Authentication, Smart Card Logon
    auth_oids = ["2.5.29.37.0", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2"]

    # Certificate Request Agent
    agent_oid = "1.3.6.1.4.1.311.20.2.1" 

    # Manager Approval
    CT_FLAG_PEND_ALL_REQUESTS = 0x00000002 
    
    # https://github.com/ly4k/Certipy/blob/main/certipy/lib/constants.py#L283
    enroll_right = "0e10c968-78fb-11d2-90d4-00c04f79dc55"

    if (((template["msPKI-Template-Schema-Version"] == 1 and template["msPKI-RA-Signature"] == 0) or
    (template["msPKI-Template-Schema-Version"] >= 2 and template["msPKI-RA-Signature"] == 1 and agent_oid in template["msPKI-RA-Application-Policies"])) and
    (len(template["pKIExtendedKeyUsage"]) == 0 or any(oid in template["pKIExtendedKeyUsage"] for oid in auth_oids)) and
    (CT_FLAG_PEND_ALL_REQUESTS & template["msPKI-Enrollment-Flag"]) != CT_FLAG_PEND_ALL_REQUESTS):
        enabled = False
        enrollers = []
        cas = []
        
        for ca in all_cas:
            if template["Name"] in ca["attributes"]["CertificateTemplates"]:
                cas.append(ca["attributes"]["Name"])
                enabled = True
        
        if enabled:
            template = parse_template_data(template)
            security = CertifcateSecurity(template["nTSecurityDescriptor"])
            
            for sid, aces in security.aces.items():
                if enroll_right in aces["extended_rights"]:
                    sids.add(sid)
                    enrollers.append(sid)

            template["cas"] = cas            
            template["enrollers"] = enrollers            
            
            return True, template
    return False, template


def get_templates(c, domain, attr):
    search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC={',DC='.join(domain.split('.'))}"
    search_filter = "(objectClass=pkicertificatetemplate)"
    print(search_base)
    print(search_filter + "\n")
    contr = security_descriptor_control(sdflags=0x5)
    
    try:
        c.search(search_base, search_filter, search_scope=SUBTREE, attributes=attr, controls=contr)
        return c.response
    except Exception as e:
        print(f"{e}\n")
        return []


def get_cas(c, domain):
    search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC={',DC='.join(domain.split('.'))}"
    search_filter = "(objectClass=pKIEnrollmentService)"
    print(search_base)
    print(search_filter + "\n")
    
    try:
        c.search(search_base, search_filter, search_scope=SUBTREE, attributes=["Name", "CertificateTemplates"])
        return c.response
    except Exception as e:
        print(f"{e}\n")
        return []


def get_samaccountnames_from_sids(c, domains, sids):
    sids_dict = {}
    sids_not_found = sids
    sids_found = []
    
    for d in domains:
        search_base = f"DC={',DC='.join(d.split('.'))}"
        search_filter = f"(|(objectSid={')(objectSid='.join(sids_not_found)}))"
        print(search_base)
        print(search_filter + "\n")
        
        try:
            c.search(search_base, search_filter, search_scope=SUBTREE, attributes=["samAccountName", "objectSid"])
                    
            for r in c.response:            
                if "attributes" in r:
                    samAccountName = r["attributes"]["samAccountName"]
                    objectSid = r["attributes"]["objectSid"]
                    
                    if isinstance(samAccountName, str):
                        sids_dict[objectSid] = f"{d}\\{samAccountName}"
                        sids_found.append(objectSid)

            sids_not_found = [x for x in sids_not_found if x not in sids_found]
        except Exception as e:
            print(f"{e}\n")
        
    return sids_dict
    
    
def parse_template_enrollers(enrollers, sids_names):
    samAccountNames = []
    
    for e in enrollers:
        if e in sids_names:
            samAccountNames.append(sids_names[e])
        else:
            samAccountNames.append(e)
            
    return samAccountNames


def parse_hashes(hashes):
    h = hashes.split(":")
    
    if len(h) == 1:
        return f"{h[0]}:{h[0]}"
    else:
        lmhash, nthash = h
        
        if len(lmhash) == 0:
            return f"{nthash}:{nthash}"
        return f"{lmhash}:{nthash}"
            
            
def get_kerberos_principal(user):    
    creds = Credentials(usage='initiate')
    
    if user.lower() in str(creds.name).lower():
        return str(creds.name)
    return user
    

parser = argparse.ArgumentParser(add_help=True, description="Find certificate templates that can be used in the second phase of the ESC3 attack", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-d", "--domain", required=True, help="Certification authority domain")
parser.add_argument("-dd", "--other-domains", required=False, help="Other domains to use for SIDs mapping")
parser.add_argument("-u", "--username", required=True, help="Domain\\Username")
parser.add_argument("-p", "--password", required=False, help="Password")
parser.add_argument("-hh", "--hashes", required=False, help="Password hashes: LM:NT | :NT | NT")
parser.add_argument("-k", "--kerberos", required=False, action="store_true", help="Kerberos authentication using KRB5CCNAME ticket")
parser.add_argument("-dc", "--domain-controller", required=True, help="Domain controller IP/FQDN")
parser.add_argument("-s", "--scheme", default="ldap", choices=["ldap", "ldaps"], required=False, help="Use LDAP or LDAPS")
args = parser.parse_args()

date = datetime.now().strftime("%d/%m/%Y %H:%M")
print(date)

ldap_server_url = f"{args.scheme}://{args.domain_controller}"
print(f"Url: {ldap_server_url}")
server = Server(ldap_server_url, get_info=ALL)

if(args.kerberos):
    principal = get_kerberos_principal(args.username.split("\\")[0])
    conn = Connection(server, user=principal, authentication=SASL, sasl_mechanism=KERBEROS)
else:
    if args.password:
        pwd = args.password
    else:
        pwd = parse_hashes(args.hashes)
    conn = Connection(server, user=args.username, password=pwd, authentication=NTLM)

if not conn.bind():
    print(f"Failed to bind to server: {conn.result}")
else:
    print("Successfully connected and authenticated to LDAP server\n")
    attributes = ["Name", "msPKI-Template-Schema-Version", "pKIExtendedKeyUsage", "msPKI-RA-Signature", "msPKI-RA-Application-Policies", "msPKI-Enrollment-Flag", "nTSecurityDescriptor"]
    templates = get_templates(conn, args.domain, attributes)
    
    if len(templates) > 0:
        cas = get_cas(conn, args.domain)
        
        if len(cas) > 0:
            valid_templates = []
            all_sids = set()

            if args.other_domains:
                all_domains = args.other_domains.split(",")
                all_domains.insert(0, args.domain)
            else:
                all_domains = [args.domain]
            
            for entry in templates[1:]:
                valid, t = parse_template(conn, entry["attributes"], cas, all_domains, all_sids)

                if valid:
                    valid_templates.append(t)
            
            sids_names = get_samaccountnames_from_sids(conn, all_domains, all_sids)
            
            for vt in valid_templates:
                vt["enrollers"] = parse_template_enrollers(vt["enrollers"], sids_names)
                
                print(f"Name: {vt['Name']}")
                print(f"Schema version: {vt['msPKI-Template-Schema-Version']}")
                print(f"Authorized signatures required: {vt['msPKI-RA-Signature']}")
                print(f"Extended key usage: {vt['pKIExtendedKeyUsage']}")
                print(f"Application policies: {vt['msPKI-RA-Application-Policies']}")
                print(f"Enrollment flags: {vt['msPKI-Enrollment-Flag']}")
                print(f"Certification authorities: {vt['cas']}")
                print(f"Enrollment rights: {vt['enrollers']}")
                print()
                
            conn.unbind()
