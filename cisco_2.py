from striprtf.striprtf import rtf_to_text
# import re
with open('/home/tba/Downloads/Sample_configs_Prob 2/Sample_configs/conf_2038.rtf', 'r') as file:
    rtf_content = file.read()

    text = rtf_to_text(rtf_content)

text = [i.strip(" !\t") for i in text.split("\n")]
text = [i for i in text if i != ""]
for i in text:
    print(i)

def user_count(text):
    count = 0
    for i in text:
        if i.startswith("user"):
            count += 1
    return count
def insecure_protocol(text):
    count = 0
    for i in text:
        if i.startswith("tftp-server") or (i.startwith("ip") and i.split(" ")[1] == "http") or (i.split(" ")[1] == "ftp" and (i.split(" ")[2] == "username" or (i.split(" ")[2] == "password" and (i.split(" ")[3] == "0" or len(i.split(" ")) == 3)))):
            count += 1
    return count
def snmp(text):
    count = 0
    for i in text:
        if i.startswith("snmp-server"):
            if i.split(" ")[1]=="group" and i.split(" ")[-1] in ["noauth","v1","v2c"]:
                count += 1
    return count
def pswd(text):
    count = 0
    for i in text:
        if i.startswith("enable password"):
            if len(i.split(" ")) == 3 or i.split(" ")[2] == "0" :
                count += 1
            count += 1
    return count
def is_strong_password(password, min_length=8, char_classes=True, exclude_dict=True):
  if len(password) < min_length:
    return False
  if char_classes:
    if not any(char.isupper() for char in password):
      return False
    if not any(char.islower() for char in password):
      return False
    if not any(char.isdigit() for char in password):
      return False
    if not any(char in "!@#$%^&*_" for char in password):
      return False
  if exclude_dict:
    with open("dictionary.txt") as f:
      if any(password.lower() in line.strip() for line in f):
        return False
  return True
def find_missing_8021x_ports(text):
  missing_ports = []
  current_interface = None
  for line in text:
    if line.startswith("interface"):
      current_interface = line.split()[1]
    elif current_interface and line.startswith("shutdown"):
      current_interface = None
    elif current_interface and line.startswith("switchport mode access"):
      if not any(line.lower() for line in text if "dot1x" in line.lower()):
        missing_ports.append({
          "interface": current_interface,
          "description": "Missing 802.1x authentication"
        })

  return missing_ports
def detect_missing_syslog_reporting(config_lines=text):
  syslog_configured = False
  for line in config_lines:
    if line.startswith("logging host"):
      syslog_configured = True
      break

  if not syslog_configured:
    return {"status": "Missing syslog reporting configuration"}
  else:
    return {}
def detect_small_logging_buffer(threshold,config_lines=text):
  buffer_size = None
  for line in config_lines:
    if line.startswith("logging buffered"):
      buffer_size = int(line.split()[2])
      break

  if buffer_size and buffer_size < threshold:
    return {"status": f"Logging buffer size too small ({buffer_size}), minimum recommended: {threshold}"}
  else:
    return {}
def detect_missing_dhcp_snooping(config_lines):
  vlans = {}
  for line in config_lines:
    if line.startswith("interface"):
      current_interface = line.split()[1]
    elif current_interface and line.startswith("switchport mode access") and "vlan" in line:
      vlan_id = int(line.split()[-1])
      vlans.setdefault(vlan_id, {"interfaces": [], "dhcp_enabled": False})
      vlans[vlan_id]["interfaces"].append(current_interface)
    elif line.startswith("ip dhcp snooping"):
      for vlan_id, vlan_info in vlans.items():
        vlan_info["dhcp_enabled"] = True
    elif line.startswith("ip dhcp snooping vlan"):
      vlan_id = int(line.split()[2])
      if vlan_id in vlans:
        vlans[vlan_id]["dhcp_enabled"] = True
  missing_info = []
  for vlan_id, vlan_info in vlans.items():
    if not vlan_info["dhcp_enabled"] and vlan_info["interfaces"]:
      missing_info.append({
        "vlan": vlan_id,
        "interfaces": vlan_info["interfaces"],
        "status": "Missing DHCP snooping configuration"
      })

  return missing_info
def detect_port_security_issues(config_lines, max_mac_addresses):
  """
  Detects missing or misconfigured port security on access ports.

  Args:
      config_lines: A list of lines from the switch configuration file.
      max_mac_addresses: The maximum allowed number of MAC addresses per port.

  Returns:
      A list of dictionaries containing information about port security issues.
  """

  issues = []
  current_interface = None
  for line in config_lines:
    # Identify interface configuration block
    if line.startswith("interface"):
      current_interface = line.split()[1]
    # Check for administratively down interface
    elif current_interface and line.startswith("shutdown"):
      current_interface = None
    # Check for access mode and VLAN assignment
    elif current_interface and line.startswith("switchport mode access") and "vlan" in line:
      # Check for missing port security configuration
      if not any(line.lower() for line in config_lines if "switchport port-security" in line.lower()):
        issues.append({
          "interface": current_interface,
          "status": "Missing port security configuration",
          "severity": 1
        })
      # Check for exceeding allowed MAC addresses (if configured)
      elif any(line.lower() for line in config_lines if "switchport port-security maximum" in line.lower()):
        # Extract configured maximum MAC addresses (if possible)
        max_configured = None
        for line in config_lines:
          if line.startswith("switchport port-security maximum"):
            max_configured = int(line.split()[3])
            break
        if max_configured and max_configured > max_mac_addresses:
          issues.append({
            "interface": current_interface,
            "status": f"Configured maximum MAC addresses ({max_configured}) exceed allowed limit ({max_mac_addresses})",
            "severity": 2
          })

  return issues
def detect_missing_storm_control(config_lines):
  """
  Detects missing or misconfigured storm control on access ports.

  Args:
      config_lines: A list of lines from the switch configuration file.

  Returns:
      A list of dictionaries containing information about missing storm control.
  """

  issues = []
  current_interface = None
  for line in config_lines:
    if line.startswith("interface"):
      current_interface = line.split()[1]
    elif current_interface and line.startswith("shutdown"):
      current_interface = None
    elif current_interface and line.startswith("switchport mode access") and "vlan" in line:
      missing_controls = []
      if not any(line.lower() for line in config_lines if "storm-control broadcast level" in line.lower()):
        missing_controls.append("broadcast")
      if not any(line.lower() for line in config_lines if "storm-control multicast level" in line.lower()):
        missing_controls.append("multicast")
      if not any(line.lower() for line in config_lines if "storm-control unicast level" in line.lower()):
        missing_controls.append("unicast")

      if missing_controls:
        issues.append({
          "interface": current_interface,
          "status": f"Missing storm control for {', '.join(missing_controls)}",
          "severity": 2
        })

  return issues
def detect_missing_control_plane_policing(config_lines):
  """
  Detects missing control plane policing configuration.

  Args:
      config_lines: A list of lines from the switch configuration file.

  Returns:
      A dictionary containing information about missing control plane policing configuration.
  """

  # Flags for control plane and policy configuration
  control_plane_found = False
  policy_found = False

  for line in config_lines:
    if line.startswith("control-plane"):
      control_plane_found = True
    elif control_plane_found and line.startswith("service-policy input"):
      policy_found = True
      break

  if not control_plane_found:
    return {"status": "Missing control plane configuration"}
  elif not policy_found:
    return {"status": "Missing control plane policing policy"}
  else:
    return {}
def detect_weak_encryption(config_lines, weak_algos=["DES", "3DES", "RC2", "RC4", "MD5", "SHA-1", "WEP", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]):
  """
  Detects weak encryption algorithms in switch configuration.

  Args:
      config_lines: A list of lines from the switch configuration file.
      weak_algos: A list of weak encryption algorithms to check for (default: common weak algorithms).

  Returns:
      A list of dictionaries containing information about weak encryption usage.
  """

  weak_instances = []
  for line in config_lines:
    for algo in weak_algos:
      if any(algo.lower() in word.lower() for word in line.split()):
        weak_instances.append({
          "location": line,
          "description": f"Weak encryption algorithm found: {algo}"
        })
        break  # Exit inner loop after finding a weak algo on the line

  return weak_instances
