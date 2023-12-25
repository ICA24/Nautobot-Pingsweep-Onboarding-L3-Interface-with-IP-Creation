#!/usr/bin/env python3
import csv
import subprocess
import ipaddress
import concurrent.futures
import datetime
import requests
import urllib3
from pynautobot import api
import time
##
##
### Initiating global variables and Nautobot API object , logging Class
##
##
## Files:
log_file_path = r'logs/Pingsweep.log' 
management_subnet_csv_path= r'Management_Subnets.csv'
successful_icmps_csv_path = r'ICMP_Respone_ALL.csv' 
## Global variables:
results = []  # Make 'results' a global variable to be accessible in main() and handle_interrupt()
new_results = []  # Make 'new_results' a global variable to be accessible in main() and the subsequent onboarding section
onboarding_sleep_time = 1  # Time in secodns for how long to wait between Device Onboarding and L3 interface/IP creation
## Nautobot instantiation ; change API "url" and "token"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
onboarding_endpoint = "https://nautobot-server/api/plugins/device-onboarding/onboarding/"
verify_ssl = False
url = "https://nautobot-server/"
token = "Nautobot Token Here"  ## Guidance on Token creation: https://docs.nautobot.com/projects/core/en/v1.4.3/rest-api/authentication/#tokens
nautobot = api(url=url, token=token, verify=verify_ssl)
nautobot.http_session.verify = False
headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Token {token}",  
            'Referer': url 
        }

## Class with function for writing logs in log_file:
class Logger:
    def __init__(self):
        self.timestamp = None
    def get_timestamp(self):
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now().strftime("%Y.%m.%d-%H:%M:%S")
        return self.timestamp
    def write_log_message(self, message, force_timestamp: bool = False) -> None:
        if not isinstance(message, str):
            raise TypeError('Message must be a string')
        timestamp = self.get_timestamp()
        if not force_timestamp and isinstance(message, str):
            log_message = message
        else:
            log_message = message + " " + timestamp
        with open(log_file_path, 'a') as file:
            file.write(log_message + '\n')
logger = Logger()
##
##
### ICMP Ping sweep of MGMT subnets from Network_Plant_Master_DB_NO_AP_TEST.csv
##
##
##
## ICMP Ping sweep of MGMT subnets from Network_Plant_Master_DB_NO_AP_TEST.csv
logger.write_log_message(message=f"\nICMP pingsweep started at:",force_timestamp=True)

def check_ping(site, host):
    ## subprocess for Ubuntu is used with 3 counts and 3 second wait time; if other OS this line needs to be changed.
    ## Ubuntu Ping documentation for customization and response codes: https://manpages.ubuntu.com/manpages/xenial/man8/ping.8.html
    output = subprocess.Popen(['ping', '-c', '3', '-W', '3', str(host)], stdout=subprocess.PIPE).communicate()[0]
    if b"bytes from" in output:   # Match on response code 0 does not work for Ubuntu 22.04 so match is used here instead for string in successful ICMP's
        return site.lower(), str(host)
    else:
        return None

def save_results(results, filename):
    existing_ips = set()
    try:
        with open(filename, 'r') as file:
            csv_reader = csv.reader(file)
            next(csv_reader)
            for row in csv_reader:
                existing_ips.add(row[1])
    except FileNotFoundError:
        logger.write_log_message(message="ICMP pingsweep started at:")
    with open(filename, 'a', newline='') as file:
        csv_writer = csv.writer(file)
        for result in results:
            if result[1] not in existing_ips:
                new_results.append(result)
                csv_writer.writerow(result)
                existing_ips.add(result[1])
    return new_results

def main():
    subnet_info = []
    with open(management_subnet_csv_path, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)
        for row in csv_reader:
            site = row[0].lower()
            ip_range = row[1]
            lan_management_subnet = row[2]
            wan_management_subnet = row[3]
            subnet_info.append((site, lan_management_subnet, wan_management_subnet))
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
        futures = []
        for info in subnet_info:
            site = info[0]
            subnets = info[1:]
            for subnet in subnets:
                if subnet:
                    hosts = ipaddress.ip_network(subnet).hosts()
                    futures.extend(executor.submit(check_ping, site, host) for host in hosts)
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            results.append(result)
    ## Save the current results to the ICMP_Response_ALL.csv file if not already present
    save_results(results, successful_icmps_csv_path)


if __name__ == "__main__":
    main()  
logger.write_log_message(message="ICMP pingsweep finished at:",force_timestamp=True)


## site,ip_address values ( row based list ) are made available from ICMP pingsweep through global variable "new_results".
### These are the site,ip_address details of IP's that have responded to ICMP and are not existent already in ICMP_Respone_ALL.csv
## The bellow part of the script feeds this data through requests library ( HTTP Post ) to device-onboarding plugin API onboarding_endpoint 
## Standard HTTP requests are used as in pynautobot cannot be used for interracting with Device Onboarding plugin
##
## Device onboarding: Sending "new_results" data to Nautobot onboarding_endpoint API
##
##
## Function to handle the device onboarding request
logger.write_log_message(message=f'Onboarding started:',force_timestamp=True)
def handle_device_onboarding(site, ip_address):
    payload = {
        "site": site,
        "ip_address": ip_address,
              }
    dev_response = requests.post(onboarding_endpoint, json=payload, headers=headers, verify=verify_ssl)
    if dev_response.status_code == 201:
        logger.write_log_message(message=f"Device Onboarding job succeded: {site},{ip_address}")
    else:
        logger.write_log_message(message=f"Device Onboarding job failed: {site},{ip_address}")

## Main execution
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    for row in new_results:
        site = row[0]
        ip_address = row[1]
        executor.submit(handle_device_onboarding, site, ip_address)
logger.write_log_message(message=f'Onboarding end timestamp:',force_timestamp=True)
##
##
##
## Run get_interfaces.py to retreive through SSH the interfaces and their IP's for the IP's in new_results:
##   "new_results" are continously used for the IP addresses from which to gather data; this might be changed to query Nautobot Onboarding job results
##   Data is returned from get_interfaces.py in "returned_all_interfaces" variable 
##
##
##
from get_interfaces import main as main_get_int 
returned_all_interfaces = main_get_int(new_results)
logger.write_log_message(message=f'L3 interfaces retreived at:',force_timestamp=True)
# #
# #
# #
# # Import interfaces and IP's and link IP address ID with Device where this should be Primary IP:
# #
# #
logger.write_log_message(message=f'Waiting {onboarding_sleep_time} seconds between Device Onboarding and L3 interface/IP creation.')
time.sleep(onboarding_sleep_time)
# #
# #
# # Phase 1: Check and Create Interfaces
if returned_all_interfaces is None:
    logger.write_log_message(message="Error: 'returned_all_interfaces' is None. Exiting interface processing.")
else:
    for row in returned_all_interfaces:
            device_name, interface_name, _, _ = row
        # Retrieve device
            devices = nautobot.dcim.devices.filter(name=device_name)
            if not devices:
                logger.write_log_message(message=f"Device {device_name} not found in Nautobot. Skipping...")
                continue
            device = devices[0]  # Take the first device

            # Check if the interface exists
            interfaces = nautobot.dcim.interfaces.filter(device_id=device.id, name=interface_name)
            if interfaces:
                logger.write_log_message(message=f"Interface {interface_name} already exists on device {device_name}. Skipping...")
                continue
            interface = nautobot.dcim.interfaces.create(device=device.id, name=interface_name, type="other")  
            logger.write_log_message(message=f"Interface {interface_name} created on device {device_name}.")
logger.write_log_message(message=f'Interfaces processing finished at:',force_timestamp=True)

# Phase 2: Process IPs
if returned_all_interfaces is None:
    logger.write_log_message(message="Error: 'returned_all_interfaces' is None. Exiting IP address processing.")
else:
    logger.write_log_message(message=f"returned_all_interfaces={returned_all_interfaces}")
    for row in returned_all_interfaces:
        try:
            device_name, interface_name, ip_address, is_primary = row
            # Retrieve device and interface
            devices = nautobot.dcim.devices.filter(name=device_name)
            if not devices:
                logger.write_log_message(message=f"No device found with the name {device_name}. Skipping...")
                continue
            device = devices[0]  # Take the first device

            interfaces = nautobot.dcim.interfaces.filter(device_id=device.id, name=interface_name)
            if not interfaces:
                logger.write_log_message(message=f"Error: Interface {interface_name} not found on device {device_name}. Skipping IP assignment...")
                continue
            interface = interfaces[0]  # Take the first interface

            # Check if the IP address already exists and if it's assigned to the correct interface
            ip = nautobot.ipam.ip_addresses.get(address=ip_address)
            if ip and ip.assigned_object_id == interface.id:
                logger.write_log_message(message=f"IP {ip_address} already exists and is correctly assigned to {interface_name}. Skipping...")
            # Check if IP exists but is not assigned to inteface processed then assign it to processed interface.
            elif ip and ip.assigned_object_id != interface.id:
                logger.write_log_message(message=f"IP {ip_address} exists but is assigned elsewhere. Re-assigning to {interface_name}...")
                ip.assigned_object_id = interface.id
                ip.assigned_object_type = "dcim.interface"
                ip.save()
            else:
                # If IP doesn't exist, create and assign it
                ip = nautobot.ipam.ip_addresses.create(
                    address=ip_address,
                    assigned_object_type="dcim.interface",
                    assigned_object_id=interface.id,
                    status="active"
                )
                logger.write_log_message(message=f"IP {ip_address} created and assigned to {interface_name} on device {device_name}.")
            if is_primary == 'yes':
                device.primary_ip4 = ip.id
                device.save()
                logger.write_log_message(message=f"Set IP {ip_address} as primary for device {device_name}")
        except Exception as e:
            logger.write_log_message(message=f"Error processing row {row}: {e}")
logger.write_log_message(message="Completed IP address processing.")
timestamp_process_ip = datetime.datetime.now().strftime("%Y.%m.%d-%H:%M:%S")
logger.write_log_message(message=f'IP address processing finished at:',force_timestamp=True)