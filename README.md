# Wazuh + TheHive ---- Incident-Routing
This integration between TheHive and Wazuh enhances incident management by automatically routing alerts based on severity.  This integration helps security teams prioritize and manage incidents efficiently.

Tested on Thehive 5.3 and Wazuh 4.9.2 

# STEP 1 

On your Wazuh Server, Install The Hive Python module 

```
sudo /var/ossec/framework/python/bin/pip3 install thehive4py
```

# STEP 2 

On your Wazuh Server, Clone this repo on your wazuh server

```
git clone https://github.com/dzidulajubilee/Wazuh-TheHive---Incident-Routing.git
```

# STEP 3  - Navigate into the cloned repo and copy the necessary files into Wazuh's Integration Directory 


```

cp  custom-w2thive /var/ossec/integrations/

cp  custom-w2thive.py /var/ossec/integrations/

```

# Step 4 - Configure Permission and Ownership 

```
chmod 755 /var/ossec/integrations/custom-w2thive
chmod 755 /var/ossec/integrations/custom-w2thive.py

chown root:wazuh /var/ossec/integrations/custom-w2thive.py
chown root:wazuh /var/ossec/integrations/custom-w2thive.py

```

# STEP5 - Final integration step - enabling the integration in the Wazuh manager configuration file  <br>

Modify `/var/ossec/etc/ossec.conf` and insert the below code. You will need to insert the IP address for your The Hive server inside the `<hook_url>` tags as well as insert your API key inside the `<api_key>` tags. 

Place Below the Global Tag

```
  <integration>
    <name>custom-w2thive</name>
    <hook_url>http://0.0.0.0:9000</hook_url>
    <api_key>00000000000000000000000</api_key>
    <alert_format>json</alert_format>
  </integration>
```

Once complete, you need to restart Wazuh Manager:

`sudo systemctl restart wazuh-manager`

You should see alerts being generated under the `Alerts` and `Cases` being created in the respective tab in TheHive Instance.

***REFERENCES***<br>
[Using Wazuh and TheHive for threat protection and incident response](https://wazuh.com/blog/using-wazuh-and-thehive-for-threat-protection-and-incident-response/) <br>

 
