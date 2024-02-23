from striprtf.striprtf import rtf_to_text
file_content = []
n=int(input("Enter the number of files:"))
for i in range(n):
    file_name=input("Enter the file name:")
    with open(file_name, 'r') as file:
        rtf_content = file.read()

        text = rtf_to_text(rtf_content)
        text = [i.strip(" !\t") for i in text.split("\n")]
    file_content.append(text)
# with open('/home/tba/Downloads/Sample_configs_Prob 2/Sample_configs/conf_2038.rtf', 'r') as file:
#     rtf_content = file.read()

#     text = rtf_to_text(rtf_content)

# text = [i for i in text if i != ""]
#fix loop
#intgreate django

sev1=[1,2,6,9]
sev2=[0,3,4,5,7,8,10,11]
sev3=[12,13]


# for i in text:
#     print(i)
def fn_call_1 (n):
        f.write(f"Severity: 2\n Too many user accounts:{n}\n")

def fn_call_2 (n):
        f.write(f"Severity: 1\n Weak user passwords:{n}\n")

def fn_call_3 (n):
        f.write(f"Severity: 1\n  Missing configuration password:{n}\n")

def fn_call_4 (n):
        f.write(f"Severity: 2\n Insecure access protocols:{n}\n")

def fn_call_5 (n):
        f.write(f"Severity: 2\n Insecure SNMP access:{n}\n")

def fn_call_6 (n):
        f.write(f"Severity:2 \n Weak encryption algorithms:{n}\n")
    
def fn_call_7 (n):
        f.write(f"Severity: 1\n  Missing host authentication on access ports:{n}\n")

def fn_call_8 (n):
        f.write(f"Severity: 2\n Missing control plane policing:{n}\n")
def fn_call_9 (n):
        f.write(f"Severity: 2\n  Missing Storm control on access ports:{n}\n")
def fn_call_10_1 (n):
        f.write(f"Severity: 1\n port security config is missing on access port:{n}\n")

def fn_call_10_2 (n):
        f.write(f"Severity: 2\nnumber_of_mac_addresses configured on switch are more than what is mentioned in tool configuration:{n}\n")
def fn_call_11 (n):
        f.write(f"Severity: 2\n Missing DHCP snooping on switch:{n}\n")
def fn_call_12 (n):
        f.write(f"Severity: 3\n Missing SysLog reporting:{n}\n")

def fn_call_13 (n):
  for line in n:
    f.write(f"Severity: 3\n Too small logging buffer:{line}\n")

def user_count(line):
  count = 0
  if line.startswith("user"):
    count += 1
  return count
def insecure_protocol(line):
    text=line
    count = 0
    for i in text:
        if i=='':
            continue
        if i.startswith("tftp-server") or (i.startswith("ip") and i.split(" ")[1] == "http") or (len(i.split(" "))>1 and (i.split(" ")[1] == "ftp" and (i.split(" ")[2] == "username" or (i.split(" ")[2] == "password" and (i.split(" ")[3] == "0" or len(i.split(" ")) == 3))))):
            count += 1
    return count
def snmp(line):
    text=line
    count = 0
    for i in text:
        if i.startswith("snmp-server"):
            if i.split(" ")[1]=="group" and i.split(" ")[-1] in ["noauth","v1","v2c"]:
                count += 1
    return count
def pswd(line):
    text=line
    count = 0
    for i in text:
        if i.startswith("enable password"):
            if len(i.split(" ")) == 3 or i.split(" ")[2] == "0" :
                count += 1
            count += 1
    return count
def is_strong_password(line, min_length=8, char_classes=True):
  if line.startswith("username"):
    if len(line.split()) < 3:
      return False
    password=line.split()[-1]
  if line.startswith("password"):
     password=line.split()[-1]
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
  return True
def find_missing_8021x_ports(text):
  missing_ports = []
  current_interface = None
  # text=[text]
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
def detect_missing_syslog_reporting(line=text):
  syslog_configured = False
  for l in line:
    if l.startswith("logging host"):
      syslog_configured = True
      break

  if not syslog_configured:
    return {"status": "Missing syslog reporting configuration"}
  else:
    return {}
def detect_small_logging_buffer(threshold=10000,line=text):
  if line.startswith("logging buffered"):
    buffer_size += int(line.split()[2])

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
def detect_port_security_issues_1(max_mac_addresses=1,line=text):
  issues = []
  current_interface = None
  config_lines=[line]
  for line in config_lines:
    if line.startswith("interface"):
      current_interface = line.split()[1]
    elif current_interface and line.startswith("shutdown"):
      current_interface = None
    elif current_interface and line.startswith("switchport mode access") and "vlan" in line:
      if not any(line.lower() for line in config_lines if "switchport port-security" in line.lower()):
        issues.append({
          "interface": current_interface,
          "status": "Missing port security configuration",
          "severity": 1
        })
  return issues
def detect_port_security_issues_2(max_mac_addresses=1,line=text):
  issues = []
  current_interface = None
  config_lines=[line]
  for line in config_lines:
    if line.startswith("interface"):
      current_interface = line.split()[1]
    elif current_interface and line.startswith("shutdown"):
      current_interface = None
    elif current_interface and line.startswith("switchport mode access") and "vlan" in line:
       if any(line.lower() for line in config_lines if "switchport port-security maximum" in line.lower()):
        max_configured = None
        for line in config_lines:
          if line.startswith("switchport port-security maximum"):
            max_configured = int(line.split()[3])
            break
        if max_configured and max_configured > max_mac_addresses:
          issues.append({
            "interface": current_interface,
            "status": f"Configured maximum MAC addresses ({max_configured}) exceed allowed limit ({max_mac_addresses})",
            "severity": 2})

  return issues
def detect_missing_storm_control(line=text):

  issues = []
  current_interface = None
  if line.startswith("interface"):
    current_interface = line.split()[1]
  elif current_interface and line.startswith("shutdown"):
    current_interface = None
  elif current_interface and line.startswith("switchport mode access") and "vlan" in line:
    missing_controls = []
    config_lines=[line]
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
def detect_missing_control_plane_policing(line=text):
  control_plane_found = False
  policy_found = False

  if line.startswith("control-plane"):
    control_plane_found = True
  elif control_plane_found and line.startswith("service-policy input"):
    policy_found = True

  if not control_plane_found:
    return {"status": "Missing control plane configuration"}
  elif not policy_found:
    return {"status": "Missing control plane policing policy"}
  else:
    return {}
def detect_weak_encryption(line=text, weak_algos=["DES", "3DES", "RC2", "RC4", "MD5", "SHA-1", "WEP", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]):

  weak_instances = []
  if type(line) == str:
    for algo in weak_algos:
      if any(algo.lower() in word.lower() for word in line.split()):
        weak_instances.append({
          "location": line,
          "description": f"Weak encryption algorithm found: {algo}"
        })
  else:
    for l in line:
      for algo in weak_algos:
        if any(algo.lower() in word.lower() for word in l.split()):
          weak_instances.append({
            "location": l,
            "description": f"Weak encryption algorithm found: {algo}"
          })
  return weak_instances
fn=[user_count,
   is_strong_password,
   pswd,
   insecure_protocol,
   snmp,
   detect_weak_encryption,
   find_missing_8021x_ports,
   detect_missing_control_plane_policing,
   detect_missing_storm_control,
   detect_port_security_issues_1,
   detect_port_security_issues_2,
   detect_missing_dhcp_snooping,
   detect_small_logging_buffer,
   detect_missing_syslog_reporting
   ]
fn_call=[
   fn_call_1,
   fn_call_2,
   fn_call_3,
   fn_call_4,
   fn_call_5,
   fn_call_6,
   fn_call_7,
   fn_call_8,
   fn_call_9,
   fn_call_10_1,
   fn_call_10_2,
   fn_call_11,
   fn_call_12,
   fn_call_13
   ]
data={}
for i in file_content:
  buffer_size = None
  s1=s2=s3=0
  hostname=""
  for j in i:
    if j.startswith("hostname"):
      hostname=j.split(" ")[1]
      break
  f = open(f"templates/{hostname}.txt", "w")
  for k in i:
   for j in range(len(fn)):
      #  if j==5:continue
       if j==10:
         if fn[j](i) != 0 and fn[j](i) != [] and fn[j](i) != {} and fn[j](i) != False:
            if j in sev1:
                s1+=1
            elif j in sev2:
                s2+=1
            elif j in sev3:
                s3+=1

         if fn[j](k) != 0 and fn[j](k) != [] and fn[j](k) != {} and fn[j](k) != False:
           fn_call[j](i)
           if j in sev1:
                s1+=1
           elif j in sev2:
                s2+=1
           elif j in sev3:
                s3+=1
       else:
           continue
  data.append({"host":hostname,"s1":s1,"s2":s2,"s3":s3,"file":f"{hostname}.txt","s":s1+s2+s3})
  f.close()

from flask import Flask, render_template
app = Flask(__name__)

@app.route("/")
def table_view():
  table_data = data
  return render_template(r"table.html", data=table_data)
app.run()

