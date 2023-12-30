## Description
This script serves the following functions for Cisco Devices and **Nautobot versions under 2.0**  *(IPAM/Device Onboarding changes from >2.0 require major changes in script ; updated script will be released soon  )*:
 - Iterate through a CSV file containing network device management subnets and generate host IP's
 - Pingsweep host IP's and store for successful pings Site ( location ) and IP address.
 - ICMP_Respone_ALL.csv CSV file is used to keep track of discovered successful ICMP's data so the script can be ran and only IP's that are not already in CSV from prior runs are processed
 - Post the Site,IP Address data to Device Onboarding Plugin using  requests ( no pynautobot support ) with multi-threading 
- SSH into devices from successful pings retreive L3 interface details ( name, IP Address, subnet mask converted to CIDR )
- Based on regex match conditions for data retrieved for devices mark IP address as Primary IP address 
- Verify if interface exists for specific device and create it if missing using pynautobot
- Verify if IP address exists and if it's assigned to correct interface ; create it if missing using pynautobot
- If for entry from device L3 interface data interface/IP address is marked as Primary; assign it as Primary IP for corresponding device

## Requirements
 - Ubuntu OS ( 22.04 used for development ) 
 - Nauotobot version < 2.0 ( 1.5.13 used for development ) 
 - Nautobot Device Onboarding Plugin <= 1.2.0 please see [Device Onboarding KB](https://docs.nautobot.com/projects/device-onboarding/en/latest/admin/install/#prerequisites) for configuration guidance
 - Pynautobot version <= 1.5.1
 - Python packages from pip_packages_commands.txt installed

## Installation
 - Install required Python packages using commands from pip_packages_commands.txt
- Populate Management_Subnets.csv with Site **( must be same name in CSV and Nautobot ; create if missing in Nautobot )** ,IP_RANGE,LAN_MANAGEMENT,WAN_MANAGEMENT . For subnets use the Network address of subnet with CIDR mask.
- Change url,token to your Nautobot URL and created Token using procedure: [REST API Authentication](https://docs.nautobot.com/projects/core/en/v1.4.3/rest-api/authentication/#tokens) ; for better security Environment Variables or encryption is suggested.
- Change SSH ( SSH_USERNAME, SSH_PASSWORD )  credentials in file get_interfaces.py ; for better security Environment Variables or encryption is suggested.
- Ensure that all files from this repository are found in the directory of the python scripts including logs folder and CSV files.
- Test script, verify logs, verify effects in Nautobot.
- Allow user that will run the script rights to all files and execute permission for crontab. 777 is used only for example; this is not safe; please see [Ubuntu File Permissions KB](https://help.ubuntu.com/community/FilePermissions):
`sudo chmod -R 777 /folder/to/script/`
`sudo chmod -R +x folder/to/script/ `
- Create cronjob to run pingsweep_with_import_of_devices_and_l3_interfaces.py periodically using documentation [CronHowTo](https://help.ubuntu.com/community/CronHowto) ; for example:
`# m h dom  mon  dow command >> minute (0-59), hour (0-23, 0 = midnight), day (1-31), month (1-12), weekday (0-6, 0 = Sunday)`
`0 17 * * 1-6 cd /datadrive/pingsweep-w-import/ && /datadrive/pingsweep-w-import/pingsweep_with_import_of_devices_and_l3_interfaces.py > /datadrive/pingsweep-w-import/logs/Cronjobs.log 2>&1`
