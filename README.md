# bloodhound-quickwin
Simple script to extract useful informations from the combo BloodHound + Neo4j. Can help to choose a target.

## Prerequisites
- python3
```bash
pip3 install py2neo
pip3 install pandas
pip3 install prettytable
```
## Example
- Use your favorite [ingestor](https://github.com/fox-it/BloodHound.py) to gather ".json"
- Start your neo4j console
- Import "*.json" in [bloodhound](https://github.com/fox-it/BloodHound.py)
- Run ./bhqc.py

## Usage

### Help 
```bash
kaluche@pwn $ ./bhqc.py -h
usage: bhqc.py [-h] [-b BOLT] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--heavy] [-l] [--debug]

Quick win for bloodhound + neo4j

options:
  -h, --help            show this help message and exit
  -b BOLT, --bolt BOLT  Neo4j bolt connexion (default: bolt://127.0.0.1:7687)
  -u USERNAME, --username USERNAME
                        Neo4j username (default : neo4j)
  -p PASSWORD, --password PASSWORD
                        Neo4j password (default : neo4j)
  -d DOMAIN, --domain DOMAIN
                        Domain filtering (default: no filtering). It's case sensitive and should be mostly in UPPERCASE.
  --heavy               Using this flag to enable heavy querying (ACL, relationships, etc.) can result in durations of seconds or
                        minutes.
  -l, --list-domains    List available domains and exit.
  --debug               Debug queries, more output

```

### Run

Note that you can now :
- list available domain "-l" and exit ;
- filtering domain with "-d DOMAIN".
- enable "--heavy" querying. Depends of your dataset size (ex for me: 1000 users < 5 sec ; 6000 users ~ 2 min)

```bash
kaluche@pwn $ ./bhqc.py -p passwordNeo4JHere -d UCA.LAN  --heavy

▬▬ι═══════ﺤ  BloodHound QuickWin @ kaluche_   -═══════ι▬▬ 

###########################################################
[*] Enumerating all domains admins (rid:512|519|544) (recursive)
###########################################################

[+] Domain admins (group) 	: ADMINISTRATEURS DE L’ENTREPRISE@UCA.LAN
[+] Domain admins (group) 	: ADMINS DU DOMAINE@UCA.LAN
[+] Domain admins (group) 	: UCA_ADMINS@UCA.LAN
[+] Domain admins (enabled) 	: ADMIN1@UCA.LAN [LASTLOG: < 1 year]
[+] Domain admins (enabled) 	: ADMIN2@UCA.LAN [LASTLOG:  NEVER]
[+] Domain admins (enabled) 	: ADMIN3@UCA.LAN [LASTLOG:  NEVER]
[+] Domain admins (enabled) 	: ADMIN4@UCA.LAN [LASTLOG:  NEVER]
[+] Domain admins (enabled) 	: ADMINISTRATEUR@UCA.LAN [LASTLOG: < 1 year]
[+] Domain admins (enabled) 	: AMELIE@UCA.LAN [LASTLOG: > 3 years]
[+] Domain admins (enabled) 	: ASREP_ADMIN1@UCA.LAN [ASREP] [LASTLOG:  NEVER]
[+] Domain admins (enabled) 	: PENTEST.UCA.LAN [LASTLOG:  NEVER]
[+] Domain admins (enabled) 	: SPN_ADMIN1@UCA.LAN [SPN] [LASTLOG:  NEVER]
[+] Domain admins (disabled) 	: BRIDGET@UCA.LAN [LASTLOG:  NEVER]

###########################################################
[*] Enumerating privileges SPN
###########################################################

[+] SPN DA (enabled) 	: SPN_ADMIN1@UCA.LAN

###########################################################
[*] Enumerating privileges AS REP ROAST
###########################################################

[+] AS-Rep Roast DA (enabled) 	: ASREP_ADMIN1@UCA.LAN

###########################################################
[*] Enumerating all SPN
###########################################################

[+] SPN (enabled) 	: CLIFF@UCA.LAN
[+] SPN (enabled) 	: CONSTRAINED1@UCA.LAN
[+] SPN (enabled) 	: SPN_ADMIN1@UCA.LAN [AdminCount]
[+] SPN (enabled) 	: SPN_LIMITED1@UCA.LAN
[+] SPN (enabled) 	: UNCONSTRAIN_LIMITED1@UCA.LAN
[+] SPN (disabled) 	: KRBTGT@UCA.LAN [AdminCount]

###########################################################
[*] Enumerating AS-REP ROSTING
###########################################################

[+] AS-Rep Roast (enabled) 	: ADTEST@UCA.LAN
[+] AS-Rep Roast (enabled) 	: ASREP_ADMIN1@UCA.LAN [AdminCount]
[+] AS-Rep Roast (enabled) 	: ASREP_LIMITED1@UCA.LAN
[+] AS-Rep Roast (enabled) 	: TEST@UCA.LAN

###########################################################
[*] Enumerating Unconstrained user account
###########################################################

[+] Unconstrained user (enabled) 	: CLIFF@UCA.LAN
[+] Unconstrained user (enabled) 	: UNCONSTRAIN_LIMITED1@UCA.LAN

###########################################################
[*] Enumerating Constrained user account
###########################################################

[+] Constrained user (enabled) 	: CONSTRAINED1@UCA.LAN ['CIFS/pc1.uca.lan', 'CIFS/pc1', 'CIFS/pc1.pwn.lab']

###########################################################
[*] Enumerating Constrained computer
###########################################################

[+] Constrained computer (enabled) 	: PC1.UCA.LAN ['HTTP/pc2', 'HTTP/pc2.UCA.LAN']

###########################################################
[*] Enumerating Unconstrained computer (DC)
###########################################################

[+] Unconstrained computer (enabled) 	: DC1.UCA.LAN [Windows Server 2012 R2 Standard]

###########################################################
[*] Enumerating Unconstrained computer (not a DC)
###########################################################

[+] Unconstrained computer (enabled) 	: CERT1.UCA.LAN

###########################################################
[*] Resource-Based Constrained Delegation abuse
###########################################################

[+] RBCD : from PC2.UCA.LAN to CERT1.UCA.LAN

###########################################################
[*] Can configure Resource-Based Constrained Delegation
###########################################################

[-] No entries found

###########################################################
[*] Non-Admins who can DCSYNC
###########################################################

[+] DCSYNC (enabled) 	: DCSYNC_LIMITED1@UCA.LAN --> UCA.LAN

###########################################################
[*] LAPS Readers
###########################################################

[+] LAPS ACL : JBIDSTRUP00235@UCA.LAN--> ReadLAPSPassword --> COMP00758.UCA.LAN


###########################################################
[*] relationships - testing which group can do what to others (all)
###########################################################

[+] ACL : DNSADMINS@UCA.LAN--> WriteDacl --> MICROSOFTDNS@UCA.LAN
[+] ACL : DNSADMINS@UCA.LAN--> WriteOwner --> MICROSOFTDNS@UCA.LAN
[+] ACL : SERVEURS RAS ET IAS@UCA.LAN--> WriteDacl --> RAS AND IAS SERVERS ACCESS CHECK@UCA.LAN
[+] ACL : SERVEURS RAS ET IAS@UCA.LAN--> WriteOwner --> RAS AND IAS SERVERS ACCESS CHECK@UCA.LAN
[+] ACL : UCA_ADMINS@UCA.LAN--> DCSync --> UCA.LAN

###########################################################
[*] relationships - testing which (non admins) users can do what to others (all)
###########################################################

[+] ACL : CLIFF@UCA.LAN--> WriteSPN --> LIMITED3@UCA.LAN
[+] ACL : DCSYNC_LIMITED1@UCA.LAN--> GetChangesAll --> UCA.LAN
[+] ACL : DIE-HARDMAN@UCA.LAN--> CanPSRemote --> DC1.UCA.LAN
[+] ACL : LIMITED1@UCA.LAN--> ForceChangePassword --> LIMITED2@UCA.LAN
[+] ACL : LIMITED3@UCA.LAN--> GenericAll --> CERT1.UCA.LAN
[+] ACL : TEST@UCA.LAN--> AllExtendedRights --> FAKE01.UCA.LAN
[+] ACL : TEST@UCA.LAN--> WriteAccountRestrictions --> FAKE01.UCA.LAN

###########################################################
[*] Stats (all domains)
###########################################################

+--------------------------------------------+------------+-------+
|                Description                 | Percentage | Total |
+--------------------------------------------+------------+-------+
|                 All users                  |    N/A     |   37  |
|             All users (enabed)             |   86.49    |   32  |
|            All users (disabled)            |    8.11    |   3   |
|     Users with 'domain admins' rights      |   28.12    |   9   |
|      Not logged (all) since 6 months       |   13.51    |   5   |
|    Not logged (enabled) since 6 months     |   15.62    |   5   |
| Password not changed > 1 y (enabled only)  |   40.62    |   13  |
| Password not changed > 2 y (enabled only)  |   31.25    |   10  |
| Password not changed > 5 y (enabled only)  |    0.0     |   0   |
| Password not changed > 10 y (enabled only) |    0.0     |   0   |
|               Users with SPN               |   18.75    |   6   |
|          Users with AS REP ROAST           |    12.5    |   4   |
|               All Computers                |    N/A     |   11  |
|               LAPS Computers               |    0.0     |   0   |
+--------------------------------------------+------------+-------+
./bhqc.py -p passwordNeo4JHere -d UCA.LAN --heavy  0,26s user 0,03s system 69% cpu 0,422 total

```
