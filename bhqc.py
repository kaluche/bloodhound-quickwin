#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: kaluche
# @Date:   2020-12-08 08:29:31
# @Last Modified by:   kaluche
# @Last Modified time: 2021-03-19 08:41:44


# pip3 install py2neo
# pip3 install pandas
from py2neo import Graph
from prettytable import PrettyTable
import argparse
import datetime

def args():
	parser = argparse.ArgumentParser(description="Quick win for bloodhound + neo4j")
	parser.add_argument('-b', '--bolt', type=str, default="bolt://127.0.0.1:7687", help="Neo4j bolt connexion (default: bolt://127.0.0.1:7687)")
	parser.add_argument('-u', '--username', type=str, default="neo4j", help="Neo4j username (default : neo4j)")
	parser.add_argument('-p', '--password', type=str, default="neo4j",help="Neo4j password (default : neo4j)")
	return parser.parse_args()

def print_title(t):
	print("\n\33[34m###########################################################")
	print("[*] {}".format(t))
	print("###########################################################\33[0m\n")

def checktimestamp(val):
	val = val.split(".")[0]
	res = (datetime.datetime.now() - datetime.datetime.fromtimestamp(int(val)))
	# print(res)
	if (val) == "-1":
		return("\033[01m\033[31m NEVER\033[0m")
	if (res > datetime.timedelta(days=365 * 10)) == True:
		return("\033[31m> 10 years\033[0m")
	elif (res > datetime.timedelta(days=365 * 5)) == True:
		return("\033[31m> 5 years\033[0m")
	elif (res > datetime.timedelta(days=365 * 3)) == True:
		return("\033[31m> 3 years\033[0m")
	elif (res > datetime.timedelta(days=365 * 2)) == True:
		return("\033[35m> 2 years\033[0m")
	elif (res > datetime.timedelta(days=365 * 1)) == True:
		return("\033[35m> 1 year\033[0m")
	elif (res < datetime.timedelta(days=365 )) == True:
		return("< 1 year")

def stats_return_count(query):
	req = g.run(query).to_table()
	return req[0][0]

args = args()
try:
	g = Graph(args.bolt, auth=(args.username, args.password))
except Exception as e:
	print(e)
	exit(0)	

print_title("Enumerating all domains admins (rid:512|544) (recursive)")
req = g.run("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) 
	WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"
	RETURN DISTINCT m.name,m.enabled,m.hasspn,m.dontreqpreauth,m.unconstraineddelegation,m.lastlogontimestamp
	ORDER BY m.enabled DESC,m.name""").to_table()

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
	print("")

print_title("Enumerating privileges SPN")
req = g.run("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) 
	WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)"
	AND m.hasspn = TRUE 
	RETURN DISTINCT m.name,m.enabled 
	ORDER BY m.enabled DESC,m.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] SPN DA (disabled) \t: \33[90m{}\33[0m".format(u[0]))
	if u[1] == True:
		print("[+] SPN DA (enabled) \t: \33[92m{}\33[0m".format(u[0]))

print_title("Enumerating privileges AS REP ROAST")
req = g.run("""MATCH p=(n:Group)<-[:MemberOf*1..]-(m) 
	WHERE n.objectid =~ ".*(?i)S-1-5-.*-(512|544)" 
	AND m.dontreqpreauth = TRUE 
	RETURN DISTINCT m.name,m.enabled
	ORDER BY m.enabled DESC,m.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] AS-Rep Roast DA (disabled) \t: \33[90m{}\33[0m".format(u[0]))
	if u[1] == True:
		print("[+] AS-Rep Roast DA (enabled) \t: \33[92m{}\33[0m".format(u[0]))


print_title("Enumerating all SPN")
req = g.run("""MATCH (u:User) 
	WHERE u.hasspn = TRUE 
	RETURN u.name,u.enabled,u.admincount
	ORDER BY u.enabled DESC,u.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] SPN (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] SPN (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	print("")

print_title("Enumerating AS-REP ROSTING")
req = g.run("""MATCH (u:User) 
	WHERE u.dontreqpreauth = TRUE 
	RETURN u.name,u.enabled,u.admincount
	ORDER BY u.enabled DESC,u.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] AS-Rep Roast (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] AS-Rep Roast (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	print("")

print_title("Enumerating Unconstrained account")
req = g.run("""MATCH (u:User) 
	WHERE u.unconstraineddelegation = TRUE 
	RETURN u.name,u.enabled,u.admincount
	ORDER BY u.enabled DESC,u.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Unconstrained user (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Unconstrained user (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2] == True:
		print(" \33[93m[AdminCount]\33[0m",end="")
	print("")

print_title("Enumerating Constrained account")
req = g.run("""MATCH (u:User) 
	WHERE u.allowedtodelegate <> "null" 
	RETURN u.name,u.enabled,u.admincount,u.allowedtodelegate
	ORDER BY u.enabled DESC,u.name""").to_table()
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
	print("")

print_title("Enumerating Unconstrained computer")
req = g.run("""MATCH (u:Computer) 
	WHERE u.unconstraineddelegation = TRUE 
	RETURN u.name,u.enabled,u.operatingsystem
	ORDER BY u.enabled DESC,u.name""").to_table()
if not req:
	print('[-] No entries found')
for u in req:
	if u[1] == False:
		print("[+] Unconstrained computer (disabled) \t: \33[90m{}\33[0m".format(u[0]),end="")
	if u[1] == True:
		print("[+] Unconstrained computer (enabled) \t: \33[92m{}\33[0m".format(u[0]),end="")
	if u[2]:
		print(" \033[34m[{}]\33[0m".format(u[2]),end="")
	print("")
print_title("Stats")

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
mytable.add_row(["Users enabled and has never log",round(ALL_USER_NEVER_LOG_ENABLE * 100 / ALL_USERS_ENABLE,2), ALL_USER_NEVER_LOG_ENABLE])
print(mytable)