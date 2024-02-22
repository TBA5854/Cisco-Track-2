def check_logging_buffer_size(config_file, threshold):
    with open(config_file, 'r') as file:
        for line in file:
            if 'logging buffered' in line:
                _, size = line.split()
                if int(size) < threshold:
                    return f"Warning: Logging buffer size is too small ({size}). This may lead to syslog overflow."
    return "Logging buffer size is adequate."

config_file = 'config.txt'  
threshold = 10000 
print(check_logging_buffer_size(config_file, threshold))    