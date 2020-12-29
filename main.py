import re
import os
from shutil import copyfileobj
from datetime import datetime
import json
import dateutil.parser as dp
from time import strptime, time

#Printing the Server running time
now = datetime.now()
current_time = now.strftime("%H:%M:%S")
print("Server Running, Time: {}".format(current_time))

#Copying logs from access.log > all_access_records.log
with open(r'all_access_records.log', 'a') as output, open(r'nginx\logs\access.log', 'r') as input:
    copyfileobj(input, output)

ips = []
suspicious_ips = []
ips_dict = {}
ADD_RULE = "netsh advfirewall firewall add rule name=\"Block {}\" dir=in protocol=any action=block remoteip={}"

THRESHOLD = 5

textfile = open(r"blocked_ips.txt", "r")
ip_data = textfile.read()
ip_data = ip_data.split("\n")

with open(r'nginx\logs\access.log') as f:
    for line in f:
        lineformat = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] (?P<request>(\"(GET|POST)))""",re.IGNORECASE)
        data = re.search(lineformat, line)

        #Cleaning the data for easy use
        data = data.groupdict()
        if data["request"]=='"GET':
            data["request"] = "GET"

        if data["ipaddress"] not in ips:
            ips.append(data["ipaddress"])


        ip_address = data["ipaddress"]
        time = data["dateandtime"]
        request = data["request"]

        t = time.split()
        struct_time = strptime(t[0], "%d/%b/%Y:%H:%M:%S")
        iso_8601_time = "{}-{}-{}T{}:{}:{}+{}:{}".format(struct_time.tm_year,
                                                        struct_time.tm_mon,
                                                        struct_time.tm_mday,
                                                        struct_time.tm_hour,
                                                        struct_time.tm_min,
                                                        struct_time.tm_sec,
                                                        t[1][1:3],
                                                        t[1][-2:])
    
        parsed_time = dp.parse(iso_8601_time)
        t_in_seconds = float(parsed_time.strftime("%S"))

        if request == "GET":
            if ip_address not in ips_dict:
                ips_dict[ip_address] = {
                    "start_time" : t_in_seconds,
                    "end_time" : 0,
                    "time_difference" : 0,
                    "hits" : 1
                }
            else:
                start = float(ips_dict[ip_address]["start_time"])
                ips_dict[ip_address]["end_time"] = t_in_seconds
                
                #Time difference in seconds
                ips_dict[ip_address]["time_difference"] = t_in_seconds - start

                #Checking the hits from a specific ip address
                ips_dict[ip_address]["hits"] += 1

for ip in ips:
    if ips_dict[ip]["start_time"] > ips_dict[ip]["end_time"]:
        start_time = 60 - ips_dict[ip]["start_time"]
        ips_dict[ip]["time_difference"] = start_time + ips_dict[ip]["end_time"]

    if ips_dict[ip]["hits"]>THRESHOLD and ips_dict[ip]["time_difference"]<10:
        with open("suspicious_ips.txt","a") as f:
            f.write("This IP is suspicious: {}\n".format(ip))

        suspicious_ips.append(ip)
    else:
        pass

for ip in suspicious_ips:
    if ip not in ip_data:
        with open("blocked_ips.txt","a") as f:
            f.write(ip+"\n")
            
        rule = ADD_RULE.format(str(ip),str(ip))
        os.system('cmd /c {}'.format(rule))

print(json.dumps(ips_dict, indent=2, sort_keys=False))

#Clearing the access.log
open(r'nginx\logs\access.log', 'w').close()