# ESC3-template-2-finder

These scripts are designed to identify certificate templates that can be used in the second phase of the ESC3 attack.

## Python

### Prerequisites

```bash
$ pip install -r requirements.txt
```

### Usage

```bash
$ python3 esc3_template_2_finder.py -h

usage: esc3_template_2_finder.py [-h] -d DOMAIN [-dd OTHER_DOMAINS] -u USERNAME [-p PASSWORD] [-hh HASHES] [-k] -dc
                                 DOMAIN_CONTROLLER [-s {ldap,ldaps}]

Find certificate templates that can be used in the second phase of the ESC3 attack

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Certification authority domain
  -dd OTHER_DOMAINS, --other-domains OTHER_DOMAINS
                        Other domains to use for SIDs mapping
  -u USERNAME, --username USERNAME
                        Domain\Username
  -p PASSWORD, --password PASSWORD
                        Password
  -hh HASHES, --hashes HASHES
                        Password hashes: LM:NT | :NT | NT
  -k, --kerberos        Kerberos authentication using KRB5CCNAME ticket
  -dc DOMAIN_CONTROLLER, --domain-controller DOMAIN_CONTROLLER
                        Domain controller IP/FQDN
  -s {ldap,ldaps}, --scheme {ldap,ldaps}
                        Use LDAP or LDAPS
```

## Powershell

### Usage

```powershell
PS> Get-Help .\esc3_template_2_finder.ps1 -Detailed

SYNOPSIS
    Find certificate templates that can be used in the second phase of the ESC3 attack.

SYNTAX
    .\esc3_template_2_finder.ps1 [-Domain] <String> [[-ForeignDomain]]

PARAMETERS
    -Domain <String>
        Certification authority domain.

    -ForeignDomain [<SwitchParameter>]
        If the computer is not domain joined or is in a different forest than the target domain, the SIDs mapping will be made
        through an LDAP query.
```
