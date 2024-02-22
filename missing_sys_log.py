import re

def check_syslog_config(config_file):
    with open(config_file, 'r') as file:
        for line in file:
            if 'logging host' in line:
                ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
                if ip_address:
                    return f"Syslog reporting is configured with IP address: {ip_address[0]}"
    return "Warning: Syslog reporting configuration is missing."

config_file = 'config.txt' 
print(check_syslog_config(config_file))