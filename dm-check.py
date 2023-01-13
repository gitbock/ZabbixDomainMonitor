#!/usr/bin/python3

import argparse
from datetime import datetime

def l(msg):
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    print(dt_string+":  "+format(msg))

def check_cert_valid_days(dm_args):
    if dm_args.verbose:
        l("Starting check cert valid days for: {}".format(dm_args.domain))
    exit(0)    

def main():
    # Prepare arguments to be parsed
    argparser = argparse.ArgumentParser(
                prog = 'Zabbix Domain Checker',
                description = 'Checks domains for different metrics',
                epilog = 'Free Tool by gitbock :)')
    argparser.add_argument('-d', '--domain', required=True, help="the domain to execute the check on")
    argparser.add_argument('-c', '--check', required=True, help="check to execute. Valid names are cert-valid-days")
    argparser.add_argument('-v', '--verbose', action="store_true", help="print additional debug info")

    # execute parser
    global dm_args
    dm_args = argparser.parse_args()

    if dm_args.verbose:
        l("Parsed arguments: {}".format(vars(dm_args)))

    if dm_args.check == "cert-valid-days":
        check_cert_valid_days(dm_args)
    else:
        l("Unknown Check specified: {}".format(dm_args.check))  

    


    exit(0)


if __name__ == '__main__':
    main()


    