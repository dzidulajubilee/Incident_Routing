# Wazuh + TheHive ---- Incident-Routing
This integration between TheHive and Wazuh enhances incident management by automatically routing alerts based on severity.  This integration helps security teams prioritize and manage incidents efficiently.

Uses TheHive's public **API v1** (TheHive 5.x and 6.x). Alerts above the case threshold are promoted to a linked case. Tested on TheHive 6.0 and Wazuh 4.14.

> Still on the deprecated API v0 / `thehive4py` 1.8.2? Use release [v1.0.0](https://github.com/dzidulajubilee/Incident_Routing/releases/tag/v1.0.0).

# Lab stack (optional)

Two compose files run the same stack: TheHive 6.0, Cassandra 4.1, Elasticsearch 8.19 and Cortex 4.2 behind nginx with HTTPS. TheHive is at `https://<host>` (default login `admin@thehive.local` / `secret`, change it), Cortex at `https://<host>:9443`. Ports 9000/9001 are not published.

Before either one: `sudo sysctl -w vm.max_map_count=262144`

### Option A - `docker-compose.yml` (uses `.env` and the `nginx/` directory)

Settings and certificates are files you can see and edit.

```
cp .env.example .env                            # set THEHIVE_SECRET (openssl rand -hex 32) and SERVER_NAME
./nginx/gen-selfsigned.sh thehive.example.com   # or copy your own server.crt / server.key into nginx/certs/
docker compose up -d
```

### Option B - `docker-compose.standalone.yml` (single file, no `.env` needed)

Copy just this file anywhere and run it (Docker Compose v2.23.1+):

```
docker compose -f docker-compose.standalone.yml up -d
```

On first start, a one-shot `init` container creates a random TheHive secret and a self-signed certificate, kept in Docker volumes. The nginx config is inside the file. A `.env` is optional (certificate name, Cortex API key, versions). To use your own certificate:

```
docker compose -f docker-compose.standalone.yml cp server.crt nginx:/etc/nginx/certs/server.crt
docker compose -f docker-compose.standalone.yml cp server.key nginx:/etc/nginx/certs/server.key
docker compose -f docker-compose.standalone.yml restart nginx
```

### Wazuh with either option

Use `https://<host>` as the `<hook_url>` in STEP 5. With the self-signed certificate, set `verify_tls = False` in `custom-w2thive.py` (lab only), or copy the certificate to the Wazuh manager and set `verify_tls` to its path.

# STEP 1 

The script only needs `requests`, which ships with Wazuh's bundled Python. If it is missing:

```
sudo /var/ossec/framework/python/bin/pip3 install requests
```

`thehive4py` and `libmagic` are no longer needed.

# STEP 2 

On your Wazuh Server, Clone this repo on your wazuh server

```
git clone https://github.com/dzidulajubilee/Incident_Routing.git
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

chown root:wazuh /var/ossec/integrations/custom-w2thive
chown root:wazuh /var/ossec/integrations/custom-w2thive.py

```

# STEP 4b - Create the TheHive user and API key

The default `admin@thehive.local` account belongs to the admin organisation and cannot receive alerts. As admin, create an organisation and an analyst user for Wazuh, then generate its API key (UI: *Organisations > Add*, then *Users > Add* with profile `analyst`, then *Create API key*). Or with the API:

```
H="https://thehive.example.com"; A="admin@thehive.local:<admin password>"
curl -sk -u "$A" -H 'Content-Type: application/json' -X POST $H/api/v1/organisation -d '{"name":"SOC","description":"Wazuh alerts"}'
curl -sk -u "$A" -H 'Content-Type: application/json' -X POST $H/api/v1/user -d '{"login":"wazuh@thehive.local","name":"Wazuh integration","profile":"analyst","organisation":"SOC"}'
curl -sk -u "$A" -X POST $H/api/v1/user/wazuh@thehive.local/key/renew      # prints the API key
```

Alerts are then visible to users of that organisation, not to the admin account.

# STEP5 - Final integration step - enabling the integration in the Wazuh manager configuration file  <br>

Modify `/var/ossec/etc/ossec.conf` and insert the below code. You will need to insert the IP address for your The Hive server inside the `<hook_url>` tags as well as insert your API key inside the `<api_key>` tags. Use an API key of a TheHive user with the `analyst` profile (needs `manageAlert` and `manageCase`). To give new cases a specific status, set `case_status` at the top of `custom-w2thive.py` (for example `'InProgress'` or a custom status); leave it as `None` to use TheHive's default. For HTTPS with a self-signed certificate, set `verify_tls` at the top of `custom-w2thive.py` to your CA bundle path. 

Place Below the Global Tag

```
  <integration>
    <name>custom-w2thive</name>
    <hook_url>https://thehive.example.com</hook_url>
    <api_key>00000000000000000000000</api_key>
    <alert_format>json</alert_format>
  </integration>
```

`<hook_url>` is the base URL of TheHive: `https://<host>` behind nginx, or `http://<host>:9000` when TheHive is reached directly. Every Wazuh alert is forwarded; to send fewer, add a minimum level inside the block, for example `<level>5</level>`.

Once complete, you need to restart Wazuh Manager:

`sudo systemctl restart wazuh-manager`

You should see alerts being generated under the `Alerts` and `Cases` being created in the respective tab in TheHive Instance. New alerts get status `New`; alerts at or above `case_lvl_threshold` (11) are turned into a case (status `New`) and the alert becomes `Imported`.

To test without waiting for a real alert, run the integration by hand with a sample alert file as the `wazuh` user:

```
sudo -u wazuh /var/ossec/integrations/custom-w2thive /path/to/sample-alert.json <api_key> https://thehive.example.com
grep custom-w2thive /var/ossec/logs/integrations.log | tail
```

Errors (wrong key, certificate problems, unreachable TheHive) are written to `/var/ossec/logs/integrations.log`.

***REFERENCES***<br>
[Using Wazuh and TheHive for threat protection and incident response](https://wazuh.com/blog/using-wazuh-and-thehive-for-threat-protection-and-incident-response/) <br>



# Alerts
![Wazuh-Alert](https://github.com/user-attachments/assets/2a80de0a-3228-4439-8bbe-edf9472a4afc)

# Cases
![Wazuh - Case](https://github.com/user-attachments/assets/d84d4232-6339-4827-bd5a-3a9a0ef173bf)

 
