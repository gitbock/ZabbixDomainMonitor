#!/usr/bin/python3

from pprint import PrettyPrinter, pformat
from pyzabbix import ZabbixMetric, ZabbixSender
from socket import gaierror
from requests.adapters import HTTPAdapter, Retry
from urllib.error import HTTPError
from urllib.request import ssl, socket
from json.decoder import JSONDecodeError
import datetime
import sys
import argparse
import logging
import requests
import checkdmarc


def get_domain_file(dm_args):
    """downloads json file with domain defintions
    """
    l.info("Fetching domain file from %s", dm_args.file_url)
    headers = {}

    # Set header for retrieving raw contents from github. without only metadta received.
    headers['Accept'] = 'application/vnd.github.raw+json'
    if dm_args.auth_token:
        headers['Authorization'] = f"Bearer {dm_args.auth_token}"

    try:
        r = requests.get(url=dm_args.file_url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            l.debug("Downloaded json domain file: %s", data)
            return data
        else:
            raise Exception(
                'Error', f"Received Status Code not OK: {r.status_code}. Auth needed?")

    except HTTPError as http_e:
        l.fatal("Error fetching domains file: %s", str(http_e))
        exit(-1)
    except JSONDecodeError as json_e:
        l.fatal("Error parsing domains file: %s", str(json_e))
        exit(-1)


def check_cert_expire_days(domain_name):
    l.info("Starting SSL-Validity Checks...")
    check_result = {}
    try:
        ctx = ssl.create_default_context()
        # assume default port 443
        with socket.create_connection((domain_name, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert = ssock.getpeercert()
                l.debug("Cert received:\n %s", pformat(cert, indent=2))
                certExpire = datetime.datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                certExpireDays = (certExpire - datetime.datetime.now()).days

                check_result['cert_expire_days'] = certExpireDays
                check_result['cert_issuer'] = cert['issuer'][2][0][1]
    except gaierror as e_nosrv:
        l.error("Error Checking SSL cert for %s: %s",
                domain_name, str(e_nosrv))
        check_result['cert_expire_days'] = f"Error: Could not connect"
        check_result['cert_issuer'] = f"Error: Could not connect"
    except Exception as e:
        l.error("Error Checking SSL cert for %s: %s", domain_name, str(e))
        check_result['cert_expire_days'] = f"Error: {str(e)}"
        check_result['cert_issuer'] = f"Error: {str(e)}"
    return check_result

def check_cert_trusted(domain_name):
    """Connects to hostname per https. If cert cannot be verified, return false.

    Args:
        domain_name (str): domain name to connect and to check
    """

    check_result = {}

    # Only try once
    s = requests.Session()
    retries = Retry(total=1)
    s.mount('http://', HTTPAdapter(max_retries=retries))

    try:
        r = s.get(f"https://{domain_name}", verify=True, timeout=4)
        if r.ok:
            check_result['cert_trusted'] = True
            l.debug("Cert of %s is trusted", domain_name)

    except requests.exceptions.ConnectionError as e_connect:
        l.warning("Error: Could not connect to %s: %s",
                  domain_name, str(e_connect))
        check_result['cert_trusted'] = False

    return check_result

def check_spf_present(domain_name):
    """Checks if Domain name has valid SPF record

    Args:
        domain_name (str): Domain to check for SPF
    """
    check_result = {}
    try:
        spf_check_result = checkdmarc.query_spf_record(domain_name)
        l.info("Found SPF record for %s", domain_name)
        check_result['spf_present'] = True
    except checkdmarc.SPFRecordNotFound:
        l.debug("No SPF record found for %s", domain_name)
        check_result['spf_present'] = False
    
    return check_result

def check_dmarc_present(domain_name):
    """Checks if Domain name has valid DMARC record

    Args:
        domain_name (str): Domain to check for DMARC
    """
    check_result = {}
    try:
        dmarc_check_result = checkdmarc.query_dmarc_record(domain_name)
        l.info("Found DMARC record for %s", domain_name)
        check_result['dmarc_present'] = True
    except checkdmarc.DMARCRecordNotFound:
        l.debug("No DMARC record found for %s", domain_name)
        check_result['dmarc_present'] = False
    except (checkdmarc.DMARCRecordInWrongLocation, checkdmarc.MultipleDMARCRecords, checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe):
        l.debug("No VALID DMARC record found for %s", domain_name)
        check_result['dmarc_present'] = False
    
    return check_result

def check_dnssec(domain_name):
    """Checks if Domain name has DNSSEC enabled

    Args:
        domain_name (str): Domain to check for DNSSEC
    """
    check_result = {}
    dnssec_enabled = checkdmarc.test_dnssec(domain_name)
    if(dnssec_enabled):
        l.info("DNSSEC enabled for %s", domain_name)
        check_result['dnssec_enabled'] = True
    else:
        l.debug("DNSSEC NOT enabled for %s", domain_name)
        check_result['dnssec_enabled'] = False
    
    return check_result

def send_zabbix(zs, zh, domains_with_check_results):
    """Sends all Check results to Zabbix Server via zabbix send / trapper.
    Items need to be prepared on Zabbix to receive values.

    Args:
        check_results (dict): dict with domains and check results
        zs (str): Zabbix Server to send
        zh (str): Zabbix Host to receive
    """

    # prepare packet to send
    zabbix_packet = []
    # for all domains
    for entry in domains_with_check_results['domains']:
        # for all check results
        domain_name = entry['domain']
        for cr in entry['check_results'].keys():
            keyname = f"dm.{cr}[{domain_name}]"
            val = entry['check_results'][cr]
            chunk = ZabbixMetric(host=zh, key=keyname, value=val)
            zabbix_packet.append(chunk)

    # send via trapper
    zbx = ZabbixSender(zs, use_config=True)
    try:
        zbx_result = zbx.send(zabbix_packet)
        l.debug("Zabbix response: %s", zbx_result)
        l.info("Sent %s check results to Zabbix Server", len(zabbix_packet))
    except Exception as e:
        l.error("Error sending to Zabbix: %s", str(e))


def main():
    """
    Start main program
    """
    # Prepare arguments to be parsed
    argparser = argparse.ArgumentParser(
        prog='Zabbix Domain Checker',
        description='Fetches json with domains from URL and executes security checks for each domain. Sends results to Zabbix.',
        epilog='Example: dm-check -f https://api.github.com/x/x/domains.json -a token123 -zs 192.168.100.50 -zh domainmontitor --std-out -v')
    argparser.add_argument('-f', '--file-url', required=True,
                           help='URL to file with domain definitions')
    argparser.add_argument('-s', '--zabbix-server', required=False,
                           help='IP of Zabbix Server to send Check results')
    argparser.add_argument('-d', '--zabbix-host', required=False,
                           help='Display Name of Host on Zabbix which is expecting check results')
    argparser.add_argument('-a', '--auth-token', required=False,
                           help="Bearer Token for HTTP request when downloading file")
    argparser.add_argument('--log-stdout', action="store_true", required=False,
                           help="Also log to stdout beside log file. For debugging")
    argparser.add_argument(
        '-v', '--verbose', action="store_true", help='log additional debug info')

    # execute cmd arg parser
    dm_args = argparser.parse_args()

    # init logging to file with std. log level
    global l
    l = logging.getLogger(__name__)
    # ensure not conflicting with logger of imported modules
    l.propagate = False

    # increase log level if set on cmd line
    if dm_args.verbose:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.INFO)

    log_format = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%m/%d/%Y %H:%M:%S')
    file_log_handler = logging.FileHandler(filename='dm.log', encoding='utf-8')
    file_log_handler.setFormatter(log_format)
    l.addHandler(file_log_handler)

    # also log to std out if requested by parameter
    if dm_args.log_stdout:
        stdout_log_handler = logging.StreamHandler(sys.stdout)
        stdout_log_handler.setFormatter(log_format)
        l.addHandler(stdout_log_handler)

    l.info("-------- Starting Domain Checker --------")
    l.debug("Parsed arguments: %s", dm_args)

    # read and parse domain file
    domains_with_check_results = get_domain_file(dm_args)

    # Main loop executing checks for each domain
    for entry in domains_with_check_results['domains']:
        if not 'check_results' in entry:
            entry['check_results'] = {}
        domain_name = entry['domain']
        l.debug("----- Checks for %s starting...", domain_name)

        # Execute Cert checks if enabled
        if 'cert_checks' in entry and entry['cert_checks']:
            l.debug(
                "Cert Checks for %s enabled, executing cert checks...", domain_name)

            # check domains for ssl cert validity
            l.debug("Checking validity for domain %s", domain_name)
            entry['check_results'].update(check_cert_expire_days(domain_name))

            # check domains for cert trust
            l.debug("Checking trust for domain %s", domain_name)
            entry['check_results'].update(check_cert_trusted(domain_name))
        else:
            l.debug("Cert Checks for %s not enabled", domain_name)
            
            
        if 'dns_checks' in entry and entry['dns_checks']:
            l.debug(
                "DNS Checks for %s enabled, executing mail checks...", domain_name)

            # check for SPF presence
            l.debug("Checking SPF for domain %s", domain_name)
            entry['check_results'].update(check_spf_present(domain_name))
            
            # check for DMARC presence
            l.debug("Checking DMARC for domain %s", domain_name)
            entry['check_results'].update(check_dmarc_present(domain_name))
            
            # check for DNSSEC
            l.debug("Checking DNSSEC for domain %s", domain_name)
            entry['check_results'].update(check_dnssec(domain_name))
        else:
            l.debug("DNS Checks for %s not enabled", domain_name)

    # If parameters are present, send results to Zabbix trapper items
    if dm_args.zabbix_server:
        zserver = dm_args.zabbix_server.strip()
        if not dm_args.zabbix_host:
            l.error("Zabbix Host not set. Use -d <hostname> to set")

        else:
            zhost = dm_args.zabbix_host.strip()
            l.info("Sending check results to Zabbix Server %s for host %s...",
                   dm_args.zabbix_server, dm_args.zabbix_host)
            send_zabbix(zserver, zhost, domains_with_check_results)
    else:
        l.debug("Zabbix Server not set. Not sending to Zabbix.")

    # print final result = domain file with enriched check results
    pp = PrettyPrinter(indent=4, width=80, depth=4, compact=False)
    pretty_result = pp.pformat(domains_with_check_results)
    l.info("\n%s", pretty_result)

    exit(0)


if __name__ == '__main__':
    main()
