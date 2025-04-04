#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: kaluche
# @Date:   2020-12-08 08:29:31
# @Last Modified by:   kaluche
# @Last Update: 2023-07-17 16:30:00

# Modified some lines by shkz 2024-10-03 23:43:00 
# Now the password is passed hidden and not in plain text

from py2neo import Graph
from prettytable import PrettyTable
import argparse
import datetime
import getpass  # getpass import

def parse_args():  
    parser = argparse.ArgumentParser(description="Quick win for bloodhound + neo4j")
    parser.add_argument('-b', '--bolt', type=str, default="bolt://127.0.0.1:7687", help="Neo4j bolt connexion (default: bolt://127.0.0.1:7687)")
    parser.add_argument('-u', '--username', type=str, default="neo4j", help="Neo4j username (default: neo4j)")
    parser.add_argument('-d', '--domain', type=str, default="", help="Domain filtering (default: no filtering). It's case sensitive and should be mostly in UPPERCASE.")
    parser.add_argument('--heavy', action='store_true', help="Using this flag to enable heavy querying (ACL, relationships, etc.) can result in durations of seconds or minutes.")
    parser.add_argument('-l', '--list-domains', action='store_true', help="List available domains and exit.")
    parser.add_argument('--debug', action='store_true', help="Debug queries, more output")
    return parser.parse_args()

def print_banner():
    print("\n\33[3m▬▬ι═══════ﺤ  BloodHound QuickWin @ kaluche_   -═══════ι▬▬ \33[0m")

def print_title(t):
    print("\n\33[34m###########################################################")
    print("[*] {}".format(t))
    print("###########################################################\33[0m\n")

def print_debug(t):
    if args.debug:
        print("\33[3mquery: {}\33[0m".format(t))

def checktimestamp(val):
    val = val.split(".")[0]
    res = (datetime.datetime.now() - datetime.datetime.fromtimestamp(int(val)))
    if val == "-1":
        return("\033[95m NEVER\033[0m")
    if res > datetime.timedelta(days=365 * 10):
        return("\033[31m> 10 years\033[0m")
    elif res > datetime.timedelta(days=365 * 5):
        return("\033[31m> 5 years\033[0m")
    elif res > datetime.timedelta(days=365 * 3):
        return("\033[31m> 3 years\033[0m")
    elif res > datetime.timedelta(days=365 * 2):
        return("\033[35m> 2 years\033[0m")
    elif res > datetime.timedelta(days=365 * 1):
        return("\033[35m> 1 year\033[0m")
    else:
        return("< 1 year")

def stats_return_count(query):
    req = g.run(query).to_table()
    return req[0][0] if req else 0  # Manejo de caso si la consulta no devuelve resultados

# args var initialized once
args = parse_args()  
password = getpass.getpass(prompt="Enter Neo4j password: ")  # password passed hidden


#################
# db connect
#################
try:
    g = Graph(args.bolt, auth=(args.username, password))
except Exception as e:
    print(e)
    exit(0)


#################
# banner
#################
print_banner()

#################
# for domain filtering
#################
if args.domain:
	domain_query = ' {{domain: "{}"}}'.format(args.domain)
else:
	domain_query = ""

#################
# for listing only
#################
if args.list_domains:
	print_title("Enumerating domains")
	query = """MATCH (d:Domain) return d.name order by d.name ASC"""	
	req = g.run(query).to_table()
	print_debug(query)
	for u in req:
		print("[+] Domain name: \33[92m{}\33[0m".format(u[0]),end="")
		print("")
	exit(0)

#################
# classic queries
#################
print_title("Enumerating all domains admins (rid:512|519|544) (recursive)")
query = """MATCH p=(n:Group{domain_query})<-[:MemberOf*1..]-(m) 
	WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|519|544)"
	RETURN DISTINCT m.name,m.enabled,m.hasspn,m.dontreqpreauth,m.unconstraineddelegation,m.lastlogontimestamp,m.owned
	ORDER BY m.enabled DESC,m.name
	""".format(domain_query=domain_query)	
req = g.run(query).to_table()
print_debug(query)

for u in req:
	if u[1] == False:
		print("[+] Domain admins (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Domain admins (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[1] == None:
		print("[+] Domain admins (group) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[SPN]\33[0m",end="")
	if u[3] == True:
		print(" \33[93m[ASREP]\33[0m",end="")
	if u[4] == True:
		print(" \33[93m[UNCONSTRAINED]\33[0m",end="")
	if u[5]:
		print(" \33[94m[LASTLOG: {}]\33[0m".format(checktimestamp(str(u[5]))),end="")
	if u[6]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")



print_title("Enumerating privileges SPN")
query = """MATCH p=(n:Group{domain_query})<-[:MemberOf*1..]-(m{domain_query}) 
	WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"
	AND m.hasspn = TRUE 
	RETURN DISTINCT m.name,m.enabled,m.owned 
	ORDER BY m.enabled DESC,m.name
	""".format(domain_query=domain_query)	
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] SPN DA (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] SPN DA (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")




print_title("Enumerating privileges AS REP ROAST")
query = """MATCH p=(n:Group{domain_query})<-[:MemberOf*1..]-(m{domain_query}) 
	WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)" 
	AND m.dontreqpreauth = TRUE 
	RETURN DISTINCT m.name,m.enabled,m.owned
	ORDER BY m.enabled DESC,m.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] AS-Rep Roast DA (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] AS-Rep Roast DA (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")



print_title("Enumerating all SPN")
query = """MATCH (u:User{domain_query}) 
	WHERE u.hasspn = TRUE 
	RETURN u.name,u.enabled,u.admincount,u.owned
	ORDER BY u.enabled DESC,u.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] SPN (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] SPN (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")




print_title("Enumerating AS-REP ROSTING")
query = """MATCH (u:User{domain_query}) 
	WHERE u.dontreqpreauth = TRUE 
	RETURN u.name,u.enabled,u.admincount,u.owned
	ORDER BY u.enabled DESC,u.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] AS-Rep Roast (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] AS-Rep Roast (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")


print_title("Enumerating Unconstrained user account")
query = """MATCH (u:User{domain_query}) 
	WHERE u.unconstraineddelegation = TRUE 
	RETURN u.name,u.enabled,u.admincount,u.owned
	ORDER BY u.enabled DESC,u.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Unconstrained user (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Unconstrained user (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")


print_title("Enumerating Constrained user account")
query = """MATCH (u:User{domain_query}) 
	WHERE u.allowedtodelegate <> "null" 
	RETURN u.name,u.enabled,u.admincount,u.allowedtodelegate,u.owned
	ORDER BY u.enabled DESC,u.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Constrained user (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Constrained user (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	if u[3] != "null":
		print(" \33[35m{}\33[0m".format(u[3]),end="")
	if u[4]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")


print_title("Enumerating Constrained computer")
query = """MATCH (u:Computer{domain_query}) 
	WHERE u.allowedtodelegate <> "null" 
	RETURN u.name,u.enabled,u.admincount,u.allowedtodelegate,u.owned
	ORDER BY u.enabled DESC,u.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Constrained computer (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Constrained computer (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	if u[3] != "null":
		print(" \33[35m{}\33[0m".format(u[3]),end="")
	if u[4]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")

# MATCH (dc:Computer)-[r1:MemberOf*0..]->(g1:Group) WHERE g1.objectid =~ "S-1-5-.*-516" WITH COLLECT(dc) AS exclude 
# MATCH p=(c:Computer) WHERE NOT c IN exclude and c.unconstraineddelegation = true return p

print_title("Enumerating Unconstrained computer (DC)")
query = """MATCH (dc:Computer{domain_query})-[r1:MemberOf*0..]->(g1:Group{domain_query}) 
	WHERE g1.objectid =~ "S-1-5-.*-516"  
	AND  dc.unconstraineddelegation = TRUE
	RETURN DISTINCT dc.name,dc.enabled,dc.operatingsystem,dc.owned
	ORDER BY dc.enabled DESC,dc.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
# req = g.run("""MATCH (u:Computer)
# 	WHERE u.unconstraineddelegation = TRUE 
# 	RETURN DISTINCT u.name,u.enabled,u.operatingsystem
# 	ORDER BY u.enabled DESC,u.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Unconstrained computer (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Unconstrained computer (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \033[34m[{}]\33[0m".format(u[2]),end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")


print_title("Enumerating Unconstrained computer (not a DC)")
query = """MATCH (dc:Computer{domain_query})-[r1:MemberOf*0..]->(g1:Group{domain_query}) 
	WHERE g1.objectid =~ "S-1-5-.*-516" WITH COLLECT(dc) AS exclude 
	MATCH p=(c:Computer{domain_query}) WHERE NOT c IN exclude 
	AND c.unconstraineddelegation = TRUE
	RETURN DISTINCT c.name,c.enabled,c.operatingsystem,c.owned
	ORDER BY c.enabled DESC,c.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Unconstrained computer (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Unconstrained computer (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \033[34m[{}]\33[0m".format(u[2]),end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")



print_title("Resource-Based Constrained Delegation abuse")
query = """MATCH p=(m{domain_query})-[r:AllowedToAct]->(n{domain_query}) 
	RETURN m.name,n.name,m.owned,n.owned
	ORDER BY m.name,n.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	print("[+] RBCD : from \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print(" to \33[92m{}\33[0m".format(u[1]),end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")

# todo: testing this query against a vuln AD
print_title("Can configure Resource-Based Constrained Delegation")
query = """MATCH (admins{domain_query})-[r1:MemberOf*0..]->(g1:Group{domain_query}) 
	WHERE g1.objectid =~ "(?i).*S-1-5-.*-(512|516|518|519|520|544|548|549|551|553)" 
			OR g1.objectid =~ "(?i).*S-1-5-9.*" 
			OR g1.name =~ "EXCHANGE WINDOWS PERMISSIONS@.*" 
			OR g1.name =~ "EXCHANGE ORGANIZATION ADMINISTRATORS@.*" 
			OR g1.name =~ "EXCHANGE SERVERS@.*" 
			OR g1.name =~ "EXCHANGE ENTERPRISE SERVERS@.*" 
			OR g1.name =~ "ORGANIZATION MANAGEMENT@.*"
			OR g1.name =~ "DNSADMINS@.*" 
			WITH COLLECT(admins) AS exclude
	MATCH p=(m{domain_query})-[r:AddAllowedToAct|GenericAll|GenericWrite|Owns|WriteAccountRestrictions|WriteDacl|WriteOwner|AllExtendedRights]->(n{domain_query}) 
	WHERE NOT m IN exclude
	UNWIND r as rr 
	RETURN m.name,n.name,m.owned,n.owned,type(rr)
	ORDER BY m.name,n.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	print("[+] RBCD : configure from \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print(" --> \33[35m{}\33[0m --> \33[92m{}\33[0m".format(u[4],u[1]),end="")
	if u[3]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")

# todo: testing this query against a vuln AD
print_title("Non-Admins who can DCSYNC")
query = """MATCH (admins{domain_query})-[r1:MemberOf*0..]->(g1:Group{domain_query}) 
	WHERE g1.objectid =~ "(?i).*S-1-5-.*-(512|516|518|519|520|544|548|549|551|553)" 
			OR g1.name =~ "EXCHANGE WINDOWS PERMISSIONS@.*" 
			OR g1.name =~ "EXCHANGE ORGANIZATION ADMINISTRATORS@.*" 
			OR g1.name =~ "EXCHANGE SERVERS@.*" 
			OR g1.name =~ "EXCHANGE ENTERPRISE SERVERS@.*" 
			OR g1.name =~ "ORGANIZATION MANAGEMENT@.*" 
			OR g1.name =~ "DNSADMINS@.*" 
			WITH COLLECT(admins) AS exclude
	MATCH p=(n1{domain_query})-[:MemberOf|GetChanges|GetChangesAll*0..]->(u:Domain{domain_query}) 
	WHERE NOT n1 IN exclude and (n1:Computer or n1:User) 
	RETURN DISTINCT n1.name,n1.enabled,u.name,n1.owned
	ORDER BY u.name,n1.name
	""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] DCSYNC (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] DCSYNC (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[3] == True:
			print(" \33[91m[OWNED]\33[0m",end="") 
	if u[2] != "null":
		print(" --> \33[35m{}\33[0m".format(u[2]),end="")
	print("")


print_title("LAPS Readers")
query = """MATCH (g{domain_query})
		MATCH (u:Computer{domain_query}) 
		MATCH p=allShortestPaths((g)-[r:ReadLAPSPassword*1..]->(u)) 
		WHERE u <> g
		UNWIND r as rr 
		RETURN g.name,u.name,type(rr),u.admincount,g.owned,u.owned
		""".format(domain_query=domain_query)
req = g.run(query).to_table()
print_debug(query)
if not req:
	print('[-] No entries found')
for u in req:
	print("[+] LAPS ACL : \33[92m{}\33[0m".format(u[0]),end="") 
	if u[4]:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("--> \33[35m{}\33[0m --> \33[92m{}\33[0m".format(u[2],u[1]),end="")
	if u[3] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	if u[5] == True:
		print(" \33[91m[OWNED]\33[0m",end="")
	print("")


#########################
#########################
#########################
## ENABLE ACL TESTING, CAN LASTS FOR SECONDS/MINUTES
if args.heavy == True:
	# Filtering, if needed: MATCH p=allShortestPaths((g)-[r:ReadLAPSPassword|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(u)) 
	print_title("relationships - testing which group can do what to others (all)")
	query = """MATCH (dagroup:Group{domain_query}) WHERE dagroup.objectid =~ "(?i).*S-1-5-.*-(4|9|15|498|512|516|517|518|519|520|521|526|527|544|548)"
		OR dagroup.objectid =~ "(?i).*S-1-5.*(-4|-9|-15)"
		OR dagroup.name =~ "EXCHANGE WINDOWS PERMISSIONS@.*" 
		OR dagroup.name =~ "EXCHANGE ORGANIZATION ADMINISTRATORS@.*" 
		OR dagroup.name =~ "EXCHANGE SERVERS@.*" 
		OR dagroup.name =~ "EXCHANGE ENTERPRISE SERVERS@.*" 
		OR dagroup.name =~ "EXCHANGE TRUSTED SUBSYSTEM@.*" 
		OR dagroup.name =~ "ORGANIZATION MANAGEMENT@.*"
		OR dagroup.name =~ "DNSADMINS@.*"  
		WITH COLLECT(dagroup) AS exclude 
		
		MATCH (g:Group{domain_query}) 
			WHERE NOT g IN exclude
		MATCH (u{domain_query}) MATCH p=allShortestPaths((g)-[r]->(u)) 
			WHERE NOT g.name = u.name AND NONE(rel in r WHERE type(rel)="MemberOf") 
		UNWIND r as rr 
		RETURN DISTINCT g.name,u.name,type(rr),u.admincount,g.domain,g.owned,u.owned
		ORDER BY g.domain,g.name
		""".format(domain_query=domain_query)
	req = g.run(query).to_table()
	print_debug(query)
	if not req:
		print('[-] No entries found')
	for u in req:
		print("[+] ACL : \33[92m{}\33[0m".format(u[0]),end="")
		if u[5] == True:
			print(" \33[91m[OWNED]\33[0m",end="") 
		print("--> \33[35m{}\33[0m --> \33[92m{}\33[0m".format(u[2],u[1]),end="")
		if u[3] == True:
			print(" \33[93m[AdminCount]\33[0m",end="")
		if u[6] == True:
			print(" \33[91m[OWNED]\33[0m",end="") 
		print("")


	# Filtering: MATCH p=allShortestPaths((u1)-[r:AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(u2)) 
	print_title("relationships - testing which (non admins) users can do what to others (all)")
	query = """MATCH (admins{domain_query})-[r1:MemberOf*0..]->(g1:Group{domain_query}) 
		WHERE g1.objectid =~ "(?i).*S-1-5-.*-(512|516|518|519|520|544|548|549|551|553)" 
		OR g1.name =~ "EXCHANGE WINDOWS PERMISSIONS@.*" 
		OR g1.name =~ "EXCHANGE ORGANIZATION ADMINISTRATORS@.*" 
		OR g1.name =~ "EXCHANGE SERVERS@.*" 
		OR g1.name =~ "EXCHANGE ENTERPRISE SERVERS@.*" 
		OR g1.name =~ "ORGANIZATION MANAGEMENT@.*" 
		WITH COLLECT(admins) AS exclude
		MATCH (u1:User{domain_query})
		MATCH (u2{domain_query}) 
			WHERE NOT u1.name = u2.name  AND NOT u1 IN exclude
		MATCH p=allShortestPaths((u1)-[r]->(u2)) 
			WHERE NONE(rel in r WHERE type(rel)="MemberOf") 
		UNWIND r as rr 
		RETURN DISTINCT u1.name,u2.name,type(rr),u2.admincount,u1.owned,u2.owned,u1.domain
		ORDER BY u1.domain,u1.name
		""".format(domain_query=domain_query)
	req = g.run(query).to_table()
	print_debug(query)
	if not req:
		print('[-] No entries found')
	for u in req:
		print("[+] ACL : \33[92m{}\33[0m".format(u[0]),end="")
		if u[4] == True:
			print(" \33[91m[OWNED]\33[0m",end="") 
		print("--> \33[35m{}\33[0m --> \33[92m{}\33[0m".format(u[2],u[1]),end="")
		if u[3] == True:
			print(" \33[93m[AdminCount]\33[0m",end="")
		if u[5] == True:
			print(" \33[91m[OWNED]\33[0m",end="") 
		print("")
	
#########################
#########################
#########################

print_title("Stats (all domains)")

mytable = PrettyTable()
mytable.field_names = ["Description","Percentage","Total"]

ALL_USERS = stats_return_count("MATCH p=(u:User) RETURN count(*)")
ALL_USERS_ENABLE = stats_return_count("MATCH p=(u:User) WHERE u.enabled = TRUE RETURN count(*)")
ALL_USERS_DISABLE = stats_return_count("MATCH p=(u:User) WHERE u.enabled = FALSE RETURN count(*)")
ALL_USERS_NOT_LOGGED_SINCE = stats_return_count("MATCH p=(u:User) WHERE u.lastlogon < (datetime().epochseconds - (180 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] and u.enabled = TRUE RETURN count(u)")
PWD_SINCE_1_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (1 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
PWD_SINCE_2_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (2 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
PWD_SINCE_5_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (5 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
PWD_SINCE_10_YEAR = stats_return_count("MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (10 * 365 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] AND u.enabled = TRUE RETURN count(u)")
ALL_USERS_SPN = stats_return_count("MATCH p=(u:User) WHERE u.hasspn = TRUE RETURN count(*)")
ALL_USERS_ASREPROAST = stats_return_count("MATCH p=(u:User) WHERE u.dontreqpreauth = TRUE RETURN count(*)")
ALL_USERS_DOM_ADM = stats_return_count("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"  AND m:User RETURN count(DISTINCT m)""")
ALL_USER_NEVER_LOG_ENABLE = stats_return_count("MATCH (u:User) WHERE u.lastlogontimestamp =-1.0 AND u.enabled=TRUE RETURN count(u)")
ALL_COMPUTERS = stats_return_count("MATCH p=(u:Computer) RETURN count(*)")
LAPS_COMPUTERS = stats_return_count("MATCH (u:Computer {haslaps:true}) RETURN count(*)")

mytable.add_row(["All users","N/A", ALL_USERS])
mytable.add_row(["All users (enabed)",round(ALL_USERS_ENABLE * 100 / ALL_USERS,2), ALL_USERS_ENABLE])
mytable.add_row(["All users (disabled)",round(ALL_USERS_DISABLE * 100 / ALL_USERS,2), ALL_USERS_DISABLE])
mytable.add_row(["Users with 'domain admins' rights",round(ALL_USERS_DOM_ADM * 100 / ALL_USERS_ENABLE,2),ALL_USERS_DOM_ADM])
mytable.add_row(["Not logged (all) since 6 months",round(ALL_USERS_NOT_LOGGED_SINCE * 100 / ALL_USERS,2), ALL_USERS_NOT_LOGGED_SINCE])
mytable.add_row(["Not logged (enabled) since 6 months",round(ALL_USERS_NOT_LOGGED_SINCE * 100 / ALL_USERS_ENABLE,2), ALL_USERS_NOT_LOGGED_SINCE])
mytable.add_row(["Password not changed > 1 y (enabled only)",round(PWD_SINCE_1_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_1_YEAR])
mytable.add_row(["Password not changed > 2 y (enabled only)",round(PWD_SINCE_2_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_2_YEAR])
mytable.add_row(["Password not changed > 5 y (enabled only)",round(PWD_SINCE_5_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_5_YEAR])
mytable.add_row(["Password not changed > 10 y (enabled only)",round(PWD_SINCE_10_YEAR * 100 / ALL_USERS_ENABLE,2), PWD_SINCE_10_YEAR])
mytable.add_row(["Users with SPN",round(ALL_USERS_SPN * 100 / ALL_USERS_ENABLE,2), ALL_USERS_SPN])
mytable.add_row(["Users with AS REP ROAST",round(ALL_USERS_ASREPROAST * 100 / ALL_USERS_ENABLE,2), ALL_USERS_ASREPROAST])
mytable.add_row(["All Computers","N/A", ALL_COMPUTERS])
mytable.add_row(["LAPS Computers",round(LAPS_COMPUTERS * 100 / ALL_COMPUTERS,2), LAPS_COMPUTERS])
print(mytable)