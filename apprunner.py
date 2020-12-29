#Importing all the necessary modules
import schedule
import time
import os
from shutil import copyfileobj

#Runing the main process
def runmain():
    os.system('main.py')

#Starting the NGINX Server
os.system('start.bat')

#Repeating the process
schedule.every(10).seconds.do(runmain)
schedule.every().minutes.do(runmain)
schedule.every().day.at("10:00").do(runmain)

#Deleting the rule after certain time
def delete_rule():
    DELETE_RULE = "netsh advfirewall firewall delete rule name=\"Block {}\""

    textfile = open(r"blocked_ips.txt", "r")
    ip_data = textfile.read()
    ip_data = ip_data.split("\n")

    while("" in ip_data):
        ip_data.remove("")
    
    for ip in ip_data:
        DELETE_RULE = DELETE_RULE.format(str(ip))
        os.system('cmd /c {}'.format(DELETE_RULE))
    
    open(r'blocked_ips.txt', 'w').close()
    print("DELETED ALL THE RULES")

schedule.every(30).seconds.do(delete_rule)
# schedule.every().friday.do(delete_rule)

while True:
    try:
        schedule.run_pending()
        time.sleep(1)
    except:
        #To stop the process press Ctrl+C
        print("\nServer Stopped\n")

        #Closing the NGINX Server
        os.system('stop.bat')

        #Remaining access.log > all_access_logs.log
        with open(r'all_access_records.log', 'a') as output, open(r'nginx\logs\access.log', 'r') as input:
            copyfileobj(input, output)
        open(r'nginx\logs\access.log', 'w').close()
        
        break