import csv
import re
from netmiko import ConnectHandler
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import datetime


## Global Variables:
SSH_USERNAME = "username"
SSH_PASSWORD = "password"
new_results = []  
log_file_path = 'logs/get_interfaces.log'
failed_file="logs/get_interfaces_failures.csv" ## Connection / command syntax errors
num_threads = 128 ##  Number of threads for multi-threading
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

## Function to establish an SSH connection to the device
def ssh_connect(hostname, username, password, failed_file):
    try:
        device = {
            'device_type': 'cisco_ios',
            'ip': hostname,
            'username': username,
            'password': password,
            'fast_cli': True,
            'global_delay_factor': 50,  # Adjust the delay between each command (increase if needed)
            'conn_timeout': 15,        # Set the connection timeout to 15 seconds or a larger value
        }

        ssh_client = ConnectHandler(**device)
        return ssh_client, None
    except Exception as e:
        logger.write_log_message(message=f"Error connecting to {hostname}: {e}")
        ## Save the failed connections to a separate CSV file
        with open(failed_file, 'a', newline='') as failed_csv:
            writer = csv.writer(failed_csv)
            writer.writerow([hostname, str(e).replace('\n', ' ')])
        return None, str(e)


def subnet_to_cidr(subnet_mask):
    try:
        ## Convert subnet mask string to integer
        subnet_int = int(ipaddress.IPv4Address(subnet_mask))
        ## Count the number of set bits in the subnet mask
        cidr = sum((subnet_int >> i) & 1 for i in range(32))
        return str(cidr)
    except Exception:
        ## Return a default value if subnet_mask is not valid
        return "24"  ## Assume a default subnet prefix length of 24 if conversion fails


def get_interfaces_with_ip(ssh_client, result_file, failed_file, processed_ips):
    ## Function to extract interface names, IP addresses, and status from "show ip interface brief" command output
    try:
        ## Check if the device is in enable mode, if not, enter enable mode
        if not ssh_client.check_enable_mode():
            ssh_client.enable()  # Enter enable mode

        output = ssh_client.send_command("show ip interface brief | exclude unassigned")
        interfaces = []
        ## Regular expression pattern to match interface name, IP address, and status
        pattern = r"(\S+)\s+([\d.]+)\s+(\S+)\s+\S+"

        hostname = ssh_client.find_prompt().strip("#")
        for match in re.finditer(pattern, output, re.DOTALL):
            interface_name = match.group(1)
            ip_address = match.group(2)
            if ip_address not in processed_ips:
                is_primary = check_is_primary(hostname, interface_name)
                ## Get the subnet information by running "show running-config interface"
                interface_output = ssh_client.send_command(f"show running-config interface {interface_name}")
                subnet_match = re.search(r"ip address ([\d.]+) ([\d.]+)", interface_output)
                if subnet_match:
                    cidr = subnet_to_cidr(subnet_match.group(2))
                    ip_address_with_cidr = f"{ip_address}/{cidr}"
                else:
                    ip_address_with_cidr = f"{ip_address}/32"  ## If subnet information not found, use "/32" for single IP
                interfaces.append([hostname, interface_name, ip_address_with_cidr, is_primary])
                processed_ips.add(ip_address)

        return interfaces

    except Exception as e:
        logger.write_log_message(message=f"Error while processing interfaces: {e}")
        ## Save the failed connections to a separate CSV file
        with open(failed_file, 'a', newline='') as failed_csv:
            writer = csv.writer(failed_csv)
            writer.writerow([hostname, str(e).replace('\n', ' ')])

def check_is_primary(hostname, interface_name):
    ## Function to check if the interface is primary based on specific conditions
    if ((hostname.startswith("router") or hostname.startswith("ROUTER")) and "mgmt" in interface_name) or \
       ((hostname.startswith("router") or hostname.startswith("ROUTER")) and "voice"  in hostname and "Lo" in interface_name) or \
       ((hostname.startswith("switch") or hostname.startswith("SWITCH") or hostname.startswith("Switch")) and "DISTR" in hostname and "VlanMGMT" in interface_name) or \
       ((hostname.startswith("switch") or hostname.startswith("SWITCH") or hostname.startswith("Switch")) and "ACC" not in hostname and "GigabitEthernet0/0" in interface_name):
        return "yes"
    else:
        return ""

def process_device(site,ip_address, result_file, failed_file, processed_ips):
    ## Function to process each device's IP interfaces
    try:
        ssh_client, error_msg = ssh_connect(ip_address, SSH_USERNAME, SSH_PASSWORD, failed_file)
        if ssh_client:
            interfaces = get_interfaces_with_ip(ssh_client, result_file, failed_file, processed_ips)
            ssh_client.disconnect()
            return interfaces

    except Exception as e:
        logger.write_log_message(message=f"Error processing  {ip_address}: {e}")
        ## Save the failed connections to a separate CSV file
        with open(failed_file, 'a', newline='') as failed_csv:
            writer = csv.writer(failed_csv)
            writer.writerow([site,ip_address, str(e)])

def main(new_results):
    processed_ips = set()
    ## Collect all interfaces data in a list
    all_interfaces = []
    ## Create a thread pool with 128 threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        ## Use list comprehension to submit the tasks to the thread pool
        futures = [executor.submit(process_device, site, ip_address, 'interface_data.csv', log_file_path, processed_ips) for site, ip_address in new_results]
        ## Wait for all the tasks to complete
        for future in futures:
            try:
                interfaces = future.result()
                if interfaces:
                    all_interfaces.extend(interfaces)
            except Exception as e:
                logger.write_log_message(message=f"Error processing device: {e}")
                with open(failed_file, 'a', newline='') as failed_csv:
                    writer = csv.writer(failed_csv)
                    writer.writerow([str(e)])

    ## Append all successful data to the existing CSV file, avoiding duplicates
    if all_interfaces:
        logger.write_log_message(message=f"returned_all_interfaces = {all_interfaces}")
        return all_interfaces
    else:
        logger.write_log_message(message='all_interfaces.new_data is empty')
        pass


## Call the main function and pass new_results
if __name__ == "__main__":
    logger.write_log_message(message="Interface data collection started at:",force_timestamp=True)
    main(new_results)
    returned_all_interfaces = main(all_interfaces)
    logger.write_log_message(message="Interface data collection finished at:",force_timestamp=True)


