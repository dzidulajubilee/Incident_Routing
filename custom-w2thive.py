#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, Case

# Global configuration
alert_lvl_threshold = 7  # Alerts for rules 7 Above
case_lvl_threshold = 11  # Cases for rules 11 or greater
suricata_lvl_threshold = 3

debug_enabled = False
info_enabled = True

# Set paths and logging configuration
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)

# Set logging level based on user configuration
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)
# create the logging file handler
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


def main(args):
    try:
        logger.debug('Start main')
        logger.debug('Get alert file location')
        alert_file_location = args[1]
        logger.debug('Get TheHive URL')
        thive_url = args[3]
        logger.debug('Get TheHive API key')
        thive_api_key = args[2]
        thive_api = TheHiveApi(thive_url, thive_api_key)

        logger.debug('Open alert file')
        w_alert = json.load(open(alert_file_location))
        logger.debug('Alert data')
        logger.debug(str(w_alert))

        logger.debug('Generate JSON to dot-key-text')
        alt = pr(w_alert, '', [])
        logger.debug('Formatting description')
        formatted_alert = md_format(alt)
        logger.debug('Search artifacts')
        artifacts_dict = artifact_detect(formatted_alert)

        severity = get_alert_severity(w_alert)
        alert = generate_alert(formatted_alert, artifacts_dict, w_alert)

        logger.debug('Threshold filtering')
        if should_create_alert(w_alert):
            send_alert(alert, thive_api)

        if should_create_case(w_alert):
            create_case(alert, thive_api, severity)

    except Exception as e:
        logger.exception('Error in main: %s', e)


def pr(data, prefix, alt):
    for key, value in data.items():
        if isinstance(value, dict):
            pr(value, prefix + '.' + str(key), alt)
        else:
            alt.append((prefix + '.' + str(key) + '|||' + str(value)))
    return alt


def md_format(alt, format_alt=''):
    md_title_dict = {}
    for now in alt:
        now = now[1:]
        dot = now.split('|||')[0].find('.')
        if dot == -1:
            md_title_dict[now.split('|||')[0]] = [now]
        else:
            if now[0:dot] in md_title_dict.keys():
                (md_title_dict[now[0:dot]]).append(now)
            else:
                md_title_dict[now[0:dot]] = [now]
    for now in md_title_dict.keys():
        format_alt += '### ' + now.capitalize() + '\n' + '| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key, val = let.split('|||')[0], let.split('|||')[1]
            format_alt += '| **' + key + '** | ' + val + ' |\n'
    return format_alt


def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+', format_alt)
    artifacts_dict['url'] = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', format_alt)
    artifacts_dict['domain'] = [now.split('//')[1].split('/')[0] for now in artifacts_dict['url']]
    return artifacts_dict


def generate_alert(format_alt, artifacts_dict, w_alert):
    sourceRef = str(uuid.uuid4())[:6]
    artifacts = [AlertArtifact(dataType=key, data=val) for key, values in artifacts_dict.items() for val in values]

    if 'agent' not in w_alert:
        w_alert['agent'] = {'id': 'no agent id', 'name': 'no agent name', 'ip': 'no agent ip'}
    else:
        w_alert['agent'].setdefault('ip', 'no agent ip')

    return Alert(
        title=w_alert['rule']['description'],
        tlp=2,
        tags=[
            'wazuh',
            'rule=' + w_alert['rule']['id'],
            'agent_name=' + w_alert['agent']['name'],
            'agent_id=' + w_alert['agent']['id'],
            'agent_ip=' + w_alert['agent']['ip']
        ],
        description=format_alt,
        type='wazuh_alert',
        source='wazuh',
        sourceRef=sourceRef,
        artifacts=artifacts
    )


def should_create_alert(w_alert):
    if w_alert['rule']['groups'] == ['ids', 'suricata']:
        if 'data' in w_alert and 'alert' in w_alert['data']:
            return int(w_alert['data']['alert']['severity']) <= suricata_lvl_threshold
    else:
        return int(w_alert['rule']['level']) >= alert_lvl_threshold
    return False


def should_create_case(w_alert):
    return int(w_alert['rule']['level']) >= case_lvl_threshold


def get_alert_severity(w_alert):
    if 'data' in w_alert and 'alert' in w_alert['data']:
        return w_alert['data']['alert'].get('severity', '2')  # Default to '2' if not found
    return w_alert['rule'].get('level', '2')  # Default to '2' if not found


def send_alert(alert, thive_api):
    response = thive_api.create_alert(alert)
    if response.status_code == 201:
        logger.info('Created TheHive alert: ' + str(response.json()['id']))
    else:
        logger.error('Error creating TheHive alert: {}/{}'.format(response.status_code, response.text))


def create_case(alert, thive_api, severity):
    case_title = f"Case related to Alert: {alert.title}"
    case_description = f"Case created based on alert with ID: {alert.sourceRef}\n\nAlert details:\n{alert.description}"

    case = Case(
        title=case_title,
        description=case_description,
        tlp=2,  # Adjust TLP as needed
        tags=['wazuh', 'alert_case'],
        severity=int(severity),  # Ensure severity is an integer
        status='Open',  # You can set other statuses like 'In Progress' based on your workflow
        source='wazuh'
    )

    response = thive_api.create_case(case)
    if response.status_code == 201:
        logger.info('Created TheHive case: ' + str(response.json()['id']))
    else:
        logger.error('Error creating TheHive case: {}/{}'.format(response.status_code, response.text))


if __name__ == "__main__":
    try:
        if debug_enabled:
            logger.debug('Debug mode')
        main(sys.argv)
    except Exception as e:
        logger.exception('Error: %s', e)


