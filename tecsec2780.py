#!/usr/bin/python3                                                                                                                         
import json
import sys
import requests
import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from time import gmtime,strftime
from datetime import datetime
import os
import getopt
import re
import cats
import time


# stock_queries = ["logged_in_users","forensic-snapshot-windows-0.0.9"]

def print_help():
    print("running python " + str(sys.version_info))
    name = os.path.basename(__file__)
    print("Usage: " + name + " -i ip -n host -d -h")


def create_markdown(hostname="",ip="",osname=None,isolation_status="",snapshot_job_id="",logged_in_users="",azure_ad_groups="",auth_logs=None,dns_logs=None):

    description = "| Endpoint Compromised | {} |\n".format(hostname)
    description = description+ "|---|---|\n"
    description = description+ "| OS Version | {} |\n".format(osname)
    description = description+ "| Host | {} |\n".format(isolation_status)
    description = description+ "| IP address | {} |\n".format(ip)
    description = description+ "| Logged in User | {} |\n".format(logged_in_users)
    description = description+ "| Azure AD Groups |{} |\n".format(azure_ad_groups)
    description = description+ "\n"

    link_to_snapshot = "https://orbital.amp.cisco.com/jobs/" + snapshot_job_id + "/results"
    description = description+ "### [Link to forensic snapshot]({})\n".format(link_to_snapshot)

    description = description+ "### Application access for user the last 24 hours\n"
    description = description+ "| Time | Application | Location |\n"
    description = description+ "|------|-------------|----------|\n"
    for a in auth_logs:
        if "RADIUS" in a["application"]["name"]:
            continue
        isostr = a["isotimestamp"]
        datetime_object = datetime.strptime(isostr, "%Y-%m-%dT%H:%M:%S.%f%z")
        timestring = datetime_object.strftime("%Y-%m-%d %H:%M")
        description = description + "|" + timestring
        description = description + "|" + a["application"]["name"]
        location_ip = ""
        location_country = ""
        if a["access_device"]["ip"]:
            location_ip = a["access_device"]["ip"]
        if a["access_device"]["location"]["country"]:
            location_country = a["access_device"]["location"]["country"]
        description = description + "|" + location_ip + "/" + location_country
        description = description + "|\n"
    description = description + "|\n"
    description = description + "\n"
    description = description+ "### Suspicious DNS logs (Command and Control and Newly Seen Domains)\n"
    description = description+ "| Time | Domain | Classification |\n"
    description = description+ "|------|-------------|----------|\n"  
    for d in dns_logs:
        timestamp = d["timestamp"]
        readable_time = datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d %H:%M')
        categories = ""
        all_categories = d["categories"]
        for c in all_categories:
            categories = categories + "," +  c["label"]

        description = description + "|" + readable_time
        description = description + "|" + d["domain"]
        description = description + "|" + categories
        description = description + "|\n"
    return(description)

def create_list_of_observables(hostname="",ip="",username="",dns_logs=None):
    domains = []
    observables = []
    if hostname:
        t = {"type":"hostname","value":hostname}
        observables.append(t)
    if username:
        t = {"type":"user","value":username}
        observables.append(t)
    
    if ip:
        t = {"type":"ip","value":ip}
        observables.append(t)

    for d in dns_logs:
        if not d["domain"] in domains:
            domains.append(d["domain"])
    for d in domains:
        observable = {"type":"domain",
                      "value":d}
        observables.append(observable)
    return(observables)


def get_input_parameters(argv):

    hostname = ""
    ip = ""   
    stop = "now"
    start = "-1d"
    debug = False
    
    try:
        opts, args = getopt.getopt(argv,"dhi:n:P:S:s:")
        for opt, arg in opts:
            if opt == '-h':
                print_help()
                sys.exit(2)
            if opt == ("-d"):
                debug = True
            if opt == ("-i"):
                ip = arg
            if opt == ("-n"):
                hostname = arg
            if opt == ("-P"):
                stop = int(arg)
            if opt == ("-S"):
                start = int(arg)
         
         
                
    except Exception as err:
        
        print_help()
        sys.exit(2)
    
    if not ip and not hostname:
        print_help()
        sys.exit(2)

    
    return(hostname,ip,start,stop,debug)

def get_orbital_info(orbital_client_id,orbital_client_password,debug,ip="",hostname=""):
    o = cats.ORBITAL(client_id=orbital_client_id,client_password=orbital_client_password,debug=debug)
    o.get_token()
    nodes = []
    if ip:
        nodes.append("ip:"+ip)
    if hostname:
        nodes.append("host:"+hostname)
    print("Getting logged in Users")
    rsp = o.stock_query("logged_in_users",nodes)
    print(json.dumps(rsp,indent=4,sort_keys=True))
    job_id = rsp["ID"]
    print("id is " + job_id)
    print("link is " + "https://orbital.amp.cisco.com/jobs/" + rsp["ID"] + "/results")
    done_count = 0
    while done_count == 0:
        time.sleep(3)
        print("waiting...")
        rsp = o.jobs(job_id)
        #print(json.dumps(rsp,indent=4,sort_keys=True))
        done_count = rsp["done_count"]
        #print("done_count is " + (str(done_count)))
    if debug:
        print("Get results for job id " + job_id)
    rsp = o.results(job_id=job_id)
    
    print(json.dumps(rsp,indent=4,sort_keys=True))
    
    logged_in_user = rsp["results"][0]["osQueryResult"][0]["values"][0]
    osname = rsp["results"][0]["hostinfo"]["osinfo"]["osname"] + rsp["results"][0]["hostinfo"]["osinfo"]["version"]
    ip = rsp["results"][0]["hostinfo"]["interfaces"]["Ethernet0"]["ipv4"]
    print("Logged in user is " + logged_in_user + " osname is " + osname)

    print("Getting Forensic snapshot")
    rsp = o.stock_query(stock_query="forensic-snapshot-windows-0.0.9",nodes=nodes)
    job_id = rsp["ID"]
    snapshot_job_id =  rsp["ID"]
    print("Forensic URL is" + snapshot_job_id)

    return(logged_in_user,ip,osname,snapshot_job_id)

def get_duo_auth_logs(api_ikey,api_skey,duo_host,logged_in_user,debug):
    duo1=cats.DUO_ADMIN(api_ikey=api_ikey,api_skey =api_skey, duo_host=duo_host, debug=debug, logfile="")
    if debug:
        print('** Users request for this user:', logged_in_user)
    r = duo1.getAuthLogs(username=logged_in_user)
    if debug:
        print(json.dumps(r,indent=4,sort_keys=True))
    auth_logs = r["response"]["authlogs"]
    return(auth_logs)

def get_umbrella_suspicious_dns(key="",secret="",hostname="",start="-1d",stop="now",debug=False):
    umb = cats.UMBRELLA2(key=key,secret=secret,debug=debug)
    rsp = umb.identities()
    if debug:
        print("Retrieved Identities")
        print(json.dumps(rsp,indent=4,sort_keys=True))    
    data = rsp["data"]
    for d in data:
        if d["label"] == hostname:
            identity = str(d["id"])
           
    rsp = umb.categories()
    data = rsp["data"]
    for d in data:
        if d["label"] == "Newly Seen Domains":
            id_newly_seen_domains = d["id"]
        if d["label"] == "Command and Control":
            id_CnC = d["id"]
    if debug:
        print("identity is "+str(identity))
        print("id_newly_seen_domain " + str(id_newly_seen_domains))
        print("id command and control is  "+ str(id_CnC))

    categories= id_CnC

    rsp = umb.reports_activity_dns(start=start,stop=stop,ip=None,identityids=identity,categories=categories,domains=None)
    print(json.dumps(rsp,indent=4,sort_keys=True))
    dns_logs = rsp["data"]
    return(dns_logs)

def create_secureX_incident(client_id="",client_secret="",markdown="",debug=False):
    now = datetime.now().isoformat()
  
    incident_obj_json = {
        "description": markdown,
        "schema_version": "1.0.11",
        "type": "incident",
        "title": "Endpoint hacked!",
        "incident_time": {
            "opened": now,
            "discovered": now,
        },
        "status": "New",
        "confidence": "High",
        "severity": "High",
        "source": "SXO - Respond to Hacked Endpoint"

    }
    ctr = cats.CTR(client_id=client_id,client_secret=client_secret,debug=debug,logfile="")
    ctr.create_incident(incident_info = incident_obj_json)

def create_secureX_casebook(client_id="",client_secret="",debug=False,logfile="",casebook_title="New Casebook",markdown="",observables_string=""):
    ctr = cats.CTR(client_id=client_id,client_secret=client_secret,debug=debug,logfile="")
    ctr.create_casebook(casebook_name="Endpoint Hacked",casebook_title=casebook_title,casebook_description=markdown,observables_string=observables_string)

def main(argv):

    (hostname,ip,start,stop,debug) = get_input_parameters(argv)

    if ip:
        print("Initiating workflow for ip " + ip)
    if hostname:
        print("Initiating workflow for host "+ hostname)

    try:
        creds = json.loads(open("creds.json").read())
        ORBITAL_CLIENT_ID = creds["orbital_client_id"]
        ORBITAL_CLIENT_PASSWORD = creds["orbital_client_password"]
        DUO_API_IKEY = creds["duo_api_ikey"]    
        DUO_API_SKEY = creds["duo_api_skey"]    
        DUO_HOST = creds["duo_host"]
        SX_CLIENT_ID = creds["sx_client_id"]
        SX_CLIENT_PASSWORD = creds["sx_client_secret"]
        WEBEX_ROOMID       = creds["webex_roomid"]
        WEBEX_TOKEN        = creds["webex_token"]
        UMBRELLA_KEY = creds["umb_api_key"]
        UMBRELLA_SECRET = creds["umb_api_secret"]
            
    except Exception as e:
        print(str(e))
        print("Failed to open creds.json")
        print("Ensure you have defined API keys in creds.json  for the script to work")

    print("-------------------------------------------------------------------------------------------------------------------------------")
    print("Orbital: Get Logged in users,osname  and take a forensic snapshot, save link for later use... This may take a minute or so!!!!")
    print("------------------------------------------------------------------------------------------------------------------------------")
    (logged_in_user,ip,osname,snapshot_job_id) = get_orbital_info(orbital_client_id=ORBITAL_CLIENT_ID,orbital_client_password=ORBITAL_CLIENT_PASSWORD,ip=ip,hostname=hostname,debug=debug)
    print("Logged in user:" + logged_in_user)
    print("osname" + osname)
    print("jobid for snapshot" + snapshot_job_id)


    print("---------------------------------------")
    print("Getting Duo auth logs")
    print("---------------------------------------")        
            
    (auth_logs) = get_duo_auth_logs(api_ikey=DUO_API_IKEY,api_skey=DUO_API_SKEY,duo_host=DUO_HOST,logged_in_user=logged_in_user,debug=debug)
   
    print(json.dumps(auth_logs,indent=4,sort_keys=True))

    print("---------------------------------------")
    print("CSE Isolation, Azure AD Group - not yet implemented")
    print("---------------------------------------")        
    isolation_status = "isolated by Secure Endpoint"
    azure_ad_groups = "Rats,SE Managers"

    print("-----------------------------------------")
    print("Getting Umbrella suspicious requests for hostname going to Command and Control or Newly Seen domains")
    print("-----------------------------------------")
    
    dns_logs = get_umbrella_suspicious_dns(key=UMBRELLA_KEY,secret=UMBRELLA_SECRET,hostname=hostname,stop=stop,start=start,debug=debug)
    print(json.dumps(dns_logs,indent=4,sort_keys=True))

    print("-------------------------------------")
    print("Create a list of observables based onUmbrella suspicious dns")
    print("-----------------------------------------")
    observables = create_list_of_observables(hostname=hostname,ip=ip,username=logged_in_user,dns_logs=dns_logs)
    print(json.dumps(observables,indent=4,sort_keys=True))

    print("-----------------------------------------")
    print("Create a report in markdown, based on our knowledge")
    print("-----------------------------------------")

    description = create_markdown(hostname=hostname,osname=osname,ip=ip,isolation_status=isolation_status,snapshot_job_id=snapshot_job_id,logged_in_users=logged_in_user,azure_ad_groups=azure_ad_groups,auth_logs=auth_logs,dns_logs=dns_logs)
    print("Markdown string is " + description)

    print("-----------------------------------------")
    print("Create a SecureX Casebook, based on the markdown string")
    print("-----------------------------------------")
    
    create_secureX_casebook(client_id=SX_CLIENT_ID,client_secret=SX_CLIENT_PASSWORD,markdown=description,observables_string=json.dumps(observables),debug=debug)
    

    print("-----------------------------------------")
    print("Post message to webex team")
    print("-----------------------------------------")
   
    w = cats.WEBEX(roomid=WEBEX_ROOMID,token=WEBEX_TOKEN)
    w.postmessage(message="Endpoint hacked",markdown=description)

if __name__ == "__main__":
    main(sys.argv[1:])
