# bloodhound-quickwin
Simple script to extract useful informations from the combo BloodHound + Neo4j. Can help to define a target.

## Prerequisites
- python3
```bash
pip3 install py2neo
pip3 install pandas
```
## Example
- Use your favorite [ingestor](https://github.com/fox-it/BloodHound.py) to gather ".json"
- Start your neo4j console
- Import "*.json" in [bloodhounnd](https://github.com/fox-it/BloodHound.py)
- Run ./bhqc.py

## Output
```bash
kaluche@pwn $ ./bhqw.py

###########################################################
[*] Enumerating all domains admins (rid:512|544) (recursive)
###########################################################

[+] Domain admins (group) 	: DOMAIN ADMINS@FBC.LAB
[+] Domain admins (group) 	: ENTERPRISE ADMINS@FBC.LAB
[+] Domain admins (group) 	: FBCDIRECTION@FBC.LAB
[+] Domain admins (enabled) 	: ADMINISTRATOR@FBC.LAB [LASTLOG: < 1 year]
[+] Domain admins (enabled) 	: DIRECTOR.TRENCH@FBC.LAB [SPN] [LASTLOG:  NEVER]
[+] Domain admins (enabled) 	: CASPER.DARLING@FBC.LAB [ASREP] [LASTLOG:  NEVER]

###########################################################
[*] Enumerating privileges SPN
###########################################################

[+] SPN DA (enabled) 	: DIRECTOR.TRENCH@FBC.LAB

###########################################################
[*] Enumerating privileges AS REP ROAST
###########################################################

[+] AS-Rep Roast DA (enabled) 	: CASPER.DARLING@FBC.LAB

###########################################################
[*] Enumerating all SPN
###########################################################

[+] SPN (enabled) 	: DYLAN.FADEN@FBC.LAB
[+] SPN (enabled) 	: ATHI@FBC.LAB
[+] SPN (enabled) 	: EMILY.POPE@FBC.LAB
[+] SPN (enabled) 	: DIRECTOR.TRENCH@FBC.LAB [AdminCount]
[+] SPN (enabled) 	: JESSE.FADEN@FBC.LAB
[+] SPN (disabled) 	: KRBTGT@FBC.LAB [AdminCount]

###########################################################
[*] Enumerating AS-REP ROSTING
###########################################################

[+] AS-Rep Roast (enabled) 	: FREDERICK.LANGSTON@FBC.LAB
[+] AS-Rep Roast (enabled) 	: CASPER.DARLING@FBC.LAB [AdminCount]

###########################################################
[*] Enumerating Unconstrained account
###########################################################

[+] Unconstrained user (enabled) 	: JESSE.FADEN@FBC.LAB

###########################################################
[*] Enumerating Constrained account
###########################################################

[+] Constrained user (enabled) 	: DYLAN.FADEN@FBC.LAB ['snmp/dc1.FBC.LAB']

###########################################################
[*] Enumerating Unconstrained computer
###########################################################

[+] Unconstrained computer (enabled) 	: DC1.FBC.LAB [Windows Server 2016 Standard]

###########################################################
[*] Stats
###########################################################

+--------------------------------------------+------------+-------+
|                Description                 | Percentage | Total |
+--------------------------------------------+------------+-------+
|                 All users                  |    N/A     |   21  |
|             All users (enabed)             |   85.71    |   18  |
|            All users (disabled)            |   14.29    |   3   |
|     Users with 'domain admins' rights      |   16.67    |   3   |
|      Not logged (all) since 6 months       |    0.0     |   0   |
|    Not logged (enabled) since 6 months     |    0.0     |   0   |
| Password not changed > 1 y (enabled only)  |    0.0     |   0   |
| Password not changed > 2 y (enabled only)  |    0.0     |   0   |
| Password not changed > 5 y (enabled only)  |    0.0     |   0   |
| Password not changed > 10 y (enabled only) |    0.0     |   0   |
|               Users with SPN               |   33.33    |   6   |
|          Users with AS REP ROAST           |   11.11    |   2   |
|      Users enabled and has never log       |   88.89    |   16  |
+--------------------------------------------+------------+-------+

```
