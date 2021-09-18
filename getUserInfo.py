#!/usr/bin/env python3

import configparser
import json
import requests
import argparse
import os.path
import os
import csv
from urllib.parse import quote


'''

Get All Teams: https://checkmarx.atlassian.net/wiki/spaces/KC/pages/1192428279/Get+All+Teams+-+GET+Teams+v2.0+and+up

Get All Roles: https://checkmarx.atlassian.net/wiki/spaces/KC/pages/1192231486/Get+All+Roles+-+GET+Roles

Get All Users: https://checkmarx.atlassian.net/wiki/spaces/KC/pages/1098646003/Get+All+Users+-+GET+Users

'''

def getAuthBearerToken (url, user, password):
    authUrl = url + "/auth/identity/connect/token"
    response = requests.post(
        authUrl,
        data={
            'username' : user,
            'password' : password,
            'grant_type' : "password",
            'scope' : "access_control_api sast_api",
            'client_id' : "resource_owner_sast_client",
            'client_secret' : "014DF517-39D1-4453-B7B3-9930C563627C"
        },
        headers={'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent' : 'PostmanRuntime/7.28.2'
        },
    )

    # print("Resp: ", response.status_code)
    if response.status_code != 200:
        return ("ERROR", response.status_code)
    json_response = response.json()
    return ("OK", json_response['access_token'])

def getTeams(baseUrl, accessToken):
    scanUrl = baseUrl + "/cxrestapi/auth/teams"
    bearerToken = "Bearer " + accessToken
    response = requests.get(
        scanUrl,
        headers={'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent' : 'PostmanRuntime/7.28.2',
            'Authorization' : bearerToken
        },
    )
    if response.status_code != 200:
        return ("ERROR", response.status_code)
    json_response = response.json()
    return ("OK", json_response)

def getRoles(baseUrl, accessToken):
    scanUrl = baseUrl + "/cxrestapi/auth/roles"
    bearerToken = "Bearer " + accessToken
    response = requests.get(
        scanUrl,
        headers={'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent' : 'PostmanRuntime/7.28.2',
            'Authorization' : bearerToken
        },
    )
    if response.status_code != 200:
        return ("ERROR", response.status_code)
    json_response = response.json()
    return ("OK", json_response)

def getAuthenticationProviders(baseUrl, accessToken):
    scanUrl = baseUrl + "/cxrestapi/auth/AuthenticationProviders"
    bearerToken = "Bearer " + accessToken
    response = requests.get(
        scanUrl,
        headers={'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent' : 'PostmanRuntime/7.28.2',
            'Authorization' : bearerToken
        },
    )
    if response.status_code != 200:
        return ("ERROR", response.status_code)
    json_response = response.json()
    return ("OK", json_response)

def getPermissions(baseUrl, accessToken):
    scanUrl = baseUrl + "/cxrestapi/auth/permissions"
    bearerToken = "Bearer " + accessToken
    response = requests.get(
        scanUrl,
        headers={'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent' : 'PostmanRuntime/7.28.2',
            'Authorization' : bearerToken
        },
    )
    if response.status_code != 200:
        return ("ERROR", response.status_code)
    json_response = response.json()
    return ("OK", json_response)

def getUsers(baseUrl, accessToken):
    scanUrl = baseUrl + "/cxrestapi/auth/users"
    bearerToken = "Bearer " + accessToken
    response = requests.get(
        scanUrl,
        headers={'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent' : 'PostmanRuntime/7.28.2',
            'Authorization' : bearerToken
        },
    )
    if response.status_code != 200:
        return ("ERROR", response.status_code)
    json_response = response.json()
    # print(json_response)
    return ("OK", json_response)
#### Main line code here #####

parser = argparse.ArgumentParser(description='Export User Information')
parser.add_argument("-c","--config",help="The config.ini location if not in the default place" )
parser.add_argument("-f","--file", default="userData.csv", help="The name of the CSV file to put the user output. Default is userData.csv" )
parser.add_argument("-r","--role", help="The name of the CSV file to put the permissions to role mapping.  If not specified, that mapping will not be performed." )
parser.add_argument("-v", action="count", default=0, help="Verbosity level for console output.  Default is none.")
args = parser.parse_args()
if args.v > 0:
    print("Starting :", os.path.basename(__file__))



configFile = ".Checkmarx\config.ini"
configBase = ''
if os.name == 'nt':
    configBase = os.environ['HOMEDRIVE']+os.environ['HOMEPATH']+'\\'
else:
    configBase = os.environ['HOME']+'/'
configFile = configBase+configFile

if args.config:
    configFile = args.config
if args.v > 0:
    print("Using config file:", configFile)

config = configparser.ConfigParser()
config.read(configFile)

if args.v > 1:
    print("Config file: ")
    for key in config['checkmarx']:
        print("Key:", key, " Value: ", config['checkmarx'][key])

# get bearer token
(status, accessToken) = getAuthBearerToken(config['checkmarx']['url'],config['checkmarx']['username'],config['checkmarx']['password'])
if status != 'OK':
    print("Error in obtaining Access Token: ", accessToken)
    print("Please double check your config file")
    exit(1)

if args.v > 0:
    print("Access Token obtained")
    print("retrieving team information...")


# get all the team names
teamDict = {}
(status, teamInfo) = getTeams(config['checkmarx']['base_url'], accessToken)
if status != 'OK':
    print("Error in obtaining team information: ", teamInfo)
    print("Make sure the user: ",config['checkmarx']['username'], " has \"Manage Roles\" and \"Manage Users\" permission in Access Control")
    exit(1)

for team in teamInfo:
    if args.v > 1:
        print("Saving Team:", team['id'], " Name: ", team['fullName'])
    teamDict[team['id']] = {}
    for key in team:
        teamDict[team['id']][key] = team[key]


# get all the role names and info
if args.v > 0:
    print ("Retrieving Role information...")
roleDict = {}
(status, roleInfo) = getRoles(config['checkmarx']['base_url'], accessToken)
if status != 'OK':
    print("Error in obtaining role information: ", roleInfo)
    print("Make sure the user: ",config['checkmarx']['username'], " has \"Manage Roles\" and \"Manage Users\" permission in Access Control")
    exit(1)
for role in roleInfo:
    if args.v > 1:
        print("Saving Role:", role['id'], " Name: ", role['name'])
    roleDict[role['id']] = {}
    for key in role:
        roleDict[role['id']][key] = role[key]


if args.v > 0:
    print ("Retrieving Auth Provider information...")

apDict = {}
(status, apInfo) = getAuthenticationProviders(config['checkmarx']['base_url'], accessToken)
if status != 'OK':
    print("Error in obtaining Authentication Provider information: ", apInfo)
    print("Make sure the user: ",config['checkmarx']['username'], " has \"Manage Roles\" and \"Manage Users\" permission in Access Control")
    exit(1)

for ap in apInfo:
    if args.v > 1:
        print("Saving AP:", ap['id'], " Name: ", ap['name'])
    apDict[ap['id']] = {}
    for key in ap:
        apDict[ap['id']][key] = ap[key]


if args.v > 0:
    print ("Retrieving User information...")
(status, userInfo) = getUsers(config['checkmarx']['base_url'], accessToken)
if status != 'OK':
    print("Error in obtaining user information: ", userInfo)
    print("Make sure the user: ",config['checkmarx']['username'], " has \"Manage Roles\" and \"Manage Users\" permission in Access Control")
    exit(1)


userList = []
for user in userInfo:
    # print(user)
    userEntry = []
    teamListStr = ''
    teamList = []
    for userTeam in user['teamIds']:
        if args.v > 0:
            print("User Team ID", userTeam, " Name: ", teamDict[userTeam]['fullName'])
        teamList.append(teamDict[userTeam]['fullName'])
        if len(teamListStr) == 0:
            teamListStr = teamDict[userTeam]['fullName']
        else:
            teamListStr = teamListStr + ", " + teamDict[userTeam]['fullName']


    roleListStr = ''
    roleList = []
    for userRole in user['roleIds']:
        if args.v > 1:
            print("User Role ID", userRole, " Name: ", roleDict[userRole]['name'])
        roleList.append(roleDict[userRole]['name'])
        if len(roleListStr) == 0:
            roleListStr = roleDict[userRole]['name']
        else:
            roleListStr = roleListStr + ", " + roleDict[userRole]['name']

    if not user['firstName']:
        user['firstName'] = ' '
    if not user['lastName']:
        user['lastName'] = ' '
    userName = user['firstName'] + " " + user['lastName']
    userEntry.append(user['active'])
    userEntry.append(userName)
    userEntry.append(user['userName'])
    userEntry.append(apDict[user['authenticationProviderId']]['name'])
    userEntry.append(user['email'])
    teamListStr = '"' + teamListStr + '"'
    userEntry.append(teamList)
    roleListStr = '"' + roleListStr + '"'
    userEntry.append(roleList)
    if not user['lastLoginDate']:
        user['lastLoginDate'] = 'NEVER'
    userEntry.append(user['lastLoginDate'])
    userEntry.append(user['creationDate'])
    userEntry.append(user['id'])



    if args.v > 1:
        print(userEntry)
    userList.append(userEntry)

fileOut = 'userJimInfo.csv'
if args.file:
    fileOut = args.file
header = ['Active','Name','Username','Authentication Provider','Email','Teams','Roles','Last Login','Creation Date','User ID']
with open(fileOut, 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)

    # write the header
    writer.writerow(header)

    # write multiple rows
    writer.writerows(userList)

if not args.role:
    exit()

# Contiue on if they want to see the roles / permissions mapping

if args.v > 0:
    print ("Generating roles to permissions mapping...")
    print ("Retrieving Permissions information...")

permissionDict = {}
(status, permissionInfo) = getPermissions(config['checkmarx']['base_url'], accessToken)
if status != 'OK':
    print("Error in obtaining team information: ", teamInfo)
    print("Make sure the user: ",config['checkmarx']['username'], " has \"Manage Roles\" and \"Manage Users\" permission in Access Control")
    exit(1)
for permission in permissionInfo:
    if args.v > 1:
        print("Saving Permission:", permission['id'], " Name: ", permission['name'])
    permissionDict[permission['id']] = {}
    for key in permission:
        permissionDict[permission['id']][key] = permission[key]

roleFileOut = args.role
rolesHeader =['Permissions\\Roles']
for role in roleDict:
        rolesHeader.append(str(roleDict[role]['name']))

with open(roleFileOut, 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)

    # write the header
    writer.writerow(rolesHeader)
    for permission in permissionDict:
        lineOut = []
        permName = '\"'+permissionDict[permission]['name']+'\"'
        lineOut.append(permName)
        for role in roleDict:
            if permission in roleDict[role]['permissionIds']:
                lineOut.append('X')
            else:
                lineOut.append(' ')

        writer.writerow(lineOut)

exit()


'''
{'id': 1,
  'userName': 'jamespintx',
  'lastLoginDate': '2021-09-14T19:32:47.2878697Z',
  'roleIds': [1, 2],
  'teamIds': [1],
  'authenticationProviderId': 1,
  'creationDate': '2021-05-06T15:17:32.5630324Z',
  'firstName': 'Jim',
  'lastName': 'Hughes',
  'email': 'jim.hughes@checkmarx.com',
  'phoneNumber': '',
  'cellPhoneNumber': '',
  'jobTitle': '',
  'other': '',
  'country': '',
  'active': True,
  'expirationDate': '2024-05-05T15:17:32.4911237Z',
  'allowedIpList': [],
  'localeId': 1}
  '''
