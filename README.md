# Wazuh + TheHive ---- Incident-Routing
This integration between TheHive and Wazuh enhances incident management by automatically routing alerts based on severity.  This integration helps security teams prioritize and manage incidents efficiently.

# Todo 

1. Install Docker on your environment dedicated for Thehive
2. Git clone "docker-compose.yml" into your environment
3. Use "docker compose up -d"  to get thehive up and running
4. Setup Wazuh 

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


 
