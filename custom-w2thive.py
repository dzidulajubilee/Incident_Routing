#!/var/ossec/framework/python/bin/python3
"""Wazuh -> TheHive integration (TheHive public API v1, TheHive 5.x and 6.x).

Called by Wazuh as: custom-w2thive <alert_file> <api_key> <hook_url>
"""
import json
import logging
import os
import re
import sys

import requests

# Global configuration
alert_lvl_threshold = 0      # Alerts for rule level 0 and above
case_lvl_threshold = 11      # Cases for rule level 11 and above
suricata_lvl_threshold = 3   # Suricata alerts with severity 1..3 (1 = highest)

# Status for new cases, e.g. 'New' or 'InProgress' (or a custom status name).
# None = let TheHive apply its default. Must be a case status that exists in TheHive.
case_status = None

verify_tls = True            # Set to False (or a CA bundle path) for self-signed TheHive certificates
request_timeout = 30

debug_enabled = False
info_enabled = True

# Logging
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger('custom-w2thive')
logger.setLevel(logging.DEBUG if debug_enabled else logging.INFO if info_enabled else logging.WARNING)
fh = logging.FileHandler(log_file)
fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(fh)


class TheHive:
    """Minimal client for TheHive API v1."""

    def __init__(self, url, api_key):
        self.url = url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': 'Bearer ' + api_key,
            'Content-Type': 'application/json',
        })
        self.session.verify = verify_tls

    def post(self, path, payload=None):
        response = self.session.post(self.url + path, json=payload or {}, timeout=request_timeout)
        if response.status_code not in (200, 201):
            raise RuntimeError('POST {} failed: {} {}'.format(path, response.status_code, response.text))
        return response.json()

    def create_alert(self, alert):
        return self.post('/api/v1/alert', alert)

    def promote_alert(self, alert_id, case_fields):
        return self.post('/api/v1/alert/{}/case'.format(alert_id), case_fields)

    def create_case(self, case):
        return self.post('/api/v1/case', case)

    def update_case(self, case_id, fields):
        response = self.session.patch('{}/api/v1/case/{}'.format(self.url, case_id), json=fields, timeout=request_timeout)
        if not response.ok:
            raise RuntimeError('PATCH case {} failed: {} {}'.format(case_id, response.status_code, response.text))


def main(args):
    alert_file_location = args[1]
    api_key = args[2]
    hive_url = args[3]
    hive = TheHive(hive_url, api_key)

    with open(alert_file_location) as f:
        w_alert = json.load(f)
    logger.debug('Alert data: %s', w_alert)

    pairs = flatten(w_alert)
    description = md_format(pairs)
    observables = detect_observables('\n'.join(str(value) for _, value in pairs))
    severity = get_alert_severity(w_alert)
    alert = generate_alert(description, observables, w_alert, severity)
    logger.debug('Generated alert: %s', alert)

    alert_id = None
    if should_create_alert(w_alert):
        created = hive.create_alert(alert)
        alert_id = created['_id']
        logger.info('Created TheHive alert: %s', alert_id)

    if should_create_case(w_alert):
        case_fields = {
            'title': 'Case related to Alert: ' + alert['title'],
            'tags': ['wazuh', 'alert_case'],
        }
        if alert_id:
            # Promote the alert so the case keeps its observables and stays linked to it
            case = hive.promote_alert(alert_id, case_fields)
            logger.info('Created TheHive case: %s', case['_id'])
            if case_status:
                hive.update_case(case['_id'], {'status': case_status})
                logger.info('Set case %s status to %s', case['_id'], case_status)
        else:
            new_case = dict(
                case_fields,
                description='Case created from Wazuh alert {}\n\n{}'.format(alert['sourceRef'], description),
                severity=severity, tlp=alert['tlp'], pap=alert['pap'],
            )
            if case_status:
                new_case['status'] = case_status
            case = hive.create_case(new_case)
            logger.info('Created TheHive case: %s', case['_id'])


def flatten(data, prefix='', out=None):
    """Turn nested JSON into ('a.b.c', value) pairs."""
    out = [] if out is None else out
    for key, value in data.items():
        path = '{}.{}'.format(prefix, key) if prefix else str(key)
        if isinstance(value, dict):
            flatten(value, path, out)
        else:
            out.append((path, value))
    return out


def md_format(pairs):
    sections = {}
    for key, value in pairs:
        sections.setdefault(key.split('.')[0], []).append((key, value))
    text = ''
    for section, rows in sections.items():
        text += '### {}\n| key | val |\n| ------ | ------ |\n'.format(section.capitalize())
        for key, value in rows:
            text += '| **{}** | {} |\n'.format(key, str(value).replace('|', '\\|').replace('\n', ' '))
    return text


def detect_observables(text):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    urls = re.findall(r'https?://[^\s)<>"\']+', text)
    domains = [u.split('//', 1)[1].split('/', 1)[0].split(':', 1)[0] for u in urls]
    observables, seen = [], set()
    for data_type, values in (('ip', ips), ('url', urls), ('domain', domains)):
        for value in values:
            if (data_type, value) not in seen:
                seen.add((data_type, value))
                observables.append({'dataType': data_type, 'data': value})
    return observables


def generate_alert(description, observables, w_alert, severity):
    agent = w_alert.setdefault('agent', {'id': 'no agent id', 'name': 'no agent name'})
    agent.setdefault('ip', 'no agent ip')
    rule = w_alert['rule']
    # Wazuh's alert id is unique per event; fall back to timestamp + rule id
    source_ref = str(w_alert.get('id') or '{}-{}'.format(w_alert.get('timestamp', ''), rule['id']))

    return {
        'type': 'wazuh_alert',
        'source': 'wazuh',
        'sourceRef': source_ref,
        'title': rule['description'],
        'description': description,
        'severity': severity,
        'tlp': 2,
        'pap': 2,
        'tags': [
            'wazuh',
            'rule=' + str(rule['id']),
            'agent_name=' + str(agent.get('name', 'no agent name')),
            'agent_id=' + str(agent.get('id', 'no agent id')),
            'agent_ip=' + str(agent['ip']),
        ],
        'observables': observables,
    }


def should_create_alert(w_alert):
    if w_alert['rule'].get('groups') == ['ids', 'suricata']:
        suricata = w_alert.get('data', {}).get('alert', {})
        return 'severity' in suricata and int(suricata['severity']) <= suricata_lvl_threshold
    return int(w_alert['rule']['level']) >= alert_lvl_threshold


def should_create_case(w_alert):
    return int(w_alert['rule']['level']) >= case_lvl_threshold


def get_alert_severity(w_alert):
    """Map Wazuh rule level to TheHive severity (1 low, 2 medium, 3 high, 4 critical)."""
    try:
        level = int(w_alert['rule']['level'])
    except (KeyError, ValueError):
        logger.error('rule.level not found in the alert data')
        return 2
    if level <= 7:
        return 1
    if level <= 11:
        return 2
    if level <= 15:
        return 3
    return 4


if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception as e:
        logger.exception('Error: %s', e)
        sys.exit(1)
