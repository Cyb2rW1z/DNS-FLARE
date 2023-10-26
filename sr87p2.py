import subprocess
import os
import socket


os.system("clear")


flag = """
██████  ███    ██ ███████               ███████ ██       █████  ██████  ███████ 
██   ██ ████   ██ ██                    ██      ██      ██   ██ ██   ██ ██      
██   ██ ██ ██  ██ ███████     █████     █████   ██      ███████ ██████  █████   
██   ██ ██  ██ ██      ██               ██      ██      ██   ██ ██   ██ ██      
██████  ██   ████ ███████               ██      ███████ ██   ██ ██   ██ ███████ 
                                                                                
                                                                                
"""
print (flag)
# Function to execute a command and save the output to a file
def execute_command_and_save_to_file(command, task_name):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout
    with open(f"tasks/{task_name}.txt", "w") as file:
        file.write(output)
    return output

# Function to display results in the terminal
def display_result(heading, content, severity):
    print(f"Severity: {severity}")
    print(heading)
    print(content)

# Rest of your code...

# Function to execute the dns-rebind tool
def execute_dns_rebind(domain):
    # Specify your desired options for dns-rebind
    interface = "eth0"  # Specify the network interface to bind to
    registered_domain = "example.com"  # Specify your registered domain name

    dns_rebind_command = f"dns-rebind -i {interface} -d {registered_domain}"

    # Run the dns-rebind tool as a subprocess
    heading = "Executing dns-rebind"
    content = execute_command_and_save_to_file(dns_rebind_command, "dns_rebind_output")
    display_result(heading, content, "high")

# Function to check DKIM TXT records
def check_dkim_records(domain):
    dkim_record = "dkim._domainkey." + domain
    heading = f"Checking DKIM Records for {dkim_record}"
    content = execute_command_and_save_to_file(f"dig {dkim_record} TXT", "dkim_records")
    display_result(heading, content, "medium")

# Function to check SOA records
def check_soa_records(domain):
    heading = f"Checking SOA Records for {domain}"
    content = execute_command_and_save_to_file(f"dig {domain} SOA", "soa_records")
    display_result(heading, content, "medium")

# Function to check DS records
def check_ds_records(domain):
    heading = f"Checking DS Records for {domain}"
    content = execute_command_and_save_to_file(f"dig {domain} DS", "ds_records")
    display_result(heading, content, "medium")

# Function to check DNSKEY records
def check_dnskey_records(domain):
    heading = f"Checking DNSKEY Records for {domain}"
    content = execute_command_and_save_to_file(f"dig {domain} DNSKEY", "dnskey_records")
    display_result(heading, content, "medium")

# Function to check CAA records
def check_caa_records(domain):
    heading = f"Checking CAA Records for {domain}"
    content = execute_command_and_save_to_file(f"dig {domain} CAA", "caa_records")
    display_result(heading, content, "medium")

# Function to check A records
def check_a_records(domain):
    heading = f"Checking A Records for {domain}"
    content = execute_command_and_save_to_file(f"dig {domain} A", "a_records")
    display_result(heading, content, "medium")

# Function to resolve DNS record and get its destination
def resolve_dns_record(record_type, domain):
    heading = f"Resolving {record_type} Record for {domain}"
    try:
        destination = socket.gethostbyname(domain)
        content = f"{record_type} record resolves to: {destination}"
        display_result(heading, content, "medium")
    except socket.gaierror:
        content = f"{record_type} record not found."
        display_result(heading, content, "medium")

# Function to perform subdomain enumeration
def perform_subdomain_enum(domain):
    response = input("Subdomain Enumeration if wanted (y/n): ")
    if response.lower() == "y":
        content = execute_command_and_save_to_file(f"assetfinder -subs-only {domain} 2>/dev/null", "subdomain_enum")
        display_result("Subdomain Enumeration Result", content, "low")
    elif response.lower() == "n":
        print("You said no.")
    else:
        print("Invalid input. Please type 'y' for yes or 'n' for no.")

# Add more functions for other record types as needed

# Function to generate the report
def generate_report(domain):
    # Create a directory to store task files
    if not os.path.exists("tasks"):
        os.mkdir("tasks")

    # Perform Zone Transfer
    heading = "Performing DNS Zone Transfer"
    content = execute_command_and_save_to_file(f"dig +short axfr {domain}", "zone_transfer")
    display_result(heading, content, "high")

    # Resolve DNS Records
    heading = "Resolving DNS Records"
    content = execute_command_and_save_to_file(f"dig +short {domain}", "dns_records")
    display_result(heading, content, "medium")

    # Find IP Address
    heading = "Finding IP Address"
    content = execute_command_and_save_to_file(f"dig +short A {domain}", "ip_address")
    display_result(heading, content, "medium")

    # Check MX Records
    heading = "Checking MX Records"
    content = execute_command_and_save_to_file(f"dig +short MX {domain}", "mx_records")
    display_result(heading, content, "medium")

    # Check TXT Records
    heading = "Checking TXT Records"
    content = execute_command_and_save_to_file(f"dig +short TXT {domain}", "txt_records")
    display_result(heading, content, "medium")

    # Check NS Records
    heading = "Checking NS Records"
    content = execute_command_and_save_to_file(f"dig +short NS {domain}", "ns_records")
    display_result(heading, content, "medium")

    # Get SSL Certificate Information
    heading = "Retrieving SSL Certificate Information"
    content = execute_command_and_save_to_file(f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -text", "ssl_certificate")
    display_result(heading, content, "high")

    # Get Web Server Headers
    heading = "Fetching Web Server Header Information"
    content = execute_command_and_save_to_file(f"curl -I {domain}", "web_server_headers")
    display_result(heading, content, "medium")

    # Use Harvester to gather ASNs
    heading = "Harvesting ASNs with theHarvester"
    content = execute_command_and_save_to_file(f"theharvester -d {domain} -b all 2>/dev/null | grep ASN", "harvester_asns")
    display_result(heading, content, "medium")

    # Check DKIM Records
    check_dkim_records(domain)

    # Check SOA Records
    check_soa_records(domain)

    # Check DS Records
    check_ds_records(domain)

    # Check DNSKEY Records
    check_dnskey_records(domain)

    # Check CAA Records
    check_caa_records(domain)

    # Check A Records
    check_a_records(domain)

    # Resolve and track DNS records
    resolve_dns_record("A", domain)
    resolve_dns_record("MX", domain)
    resolve_dns_record("TXT", domain)
    resolve_dns_record("NS", domain)
    resolve_dns_record("CNAME", domain)
    resolve_dns_record("PTR", domain)
    resolve_dns_record("SRV", domain)

    # Perform subdomain enumeration if wanted
    perform_subdomain_enum(domain)

if __name__ == "__main__":
    domain = input("Enter the domain to query: ")
    generate_report(domain)
