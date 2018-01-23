#!/usr/bin/env python3

import os
import requests
import json
import urllib3
import logging as log
from lxml import etree
from datetime import datetime, timedelta
from hashlib import md5
from argparse import ArgumentParser
from socket import gethostbyname


def get_skey(storage, login, password, use_cache=True):
    """
    Get's session key from HP MSA API.
    :param storage:
    String with storage IP address.
    :param login:
    String with MSA username.
    :param password:
    String with MSA password.
    :param use_cache:
    The function will try to save session key to disk.
    :return:
    Session key as <str> or error code as <str>
    """

    log.info("Starting function:  get_skey")
    # Determine the path to store cache skey file
    tmp_dir = '/tmp/zbx-hpmsa-dev/'
    # Create temp dir if it's not exists
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
        # Making temp dir writable for zabbix user and group
        os.chmod(tmp_dir, 0o770)
    elif not os.access(tmp_dir, 2):  # 2 - os.W_OK:
        raise SystemExit("ERROR: '{tmp}' not writable for user ['{user}'].".format(tmp=tmp_dir,
                                                                                    user=os.getenv('USER')))
    else:
        # Current dir. Yeap, it's easier than getcwd() or os.path.dirname(os.path.abspath(__file__)).
        tmp_dir = ''

    log.info("temp dir: {tmp}".format(tmp=tmp_dir))

    # Cache file name
    cache_file = tmp_dir + 'zbx-hpmsa_{strg}.skey'.format(strg=storage)
    log.info("cache_file: {cfile}".format(cfile=cache_file))


    # Trying to use cached session key
    if os.path.exists(cache_file):
        log.info("Cache file exists")
        
        cache_alive = datetime.utcnow() - timedelta(minutes=15)
        cache_file_mtime = datetime.utcfromtimestamp(os.path.getmtime(cache_file))
        log.info("Now: {now} / File: {mtime}".format(now=cache_alive,mtime=cache_file_mtime))
        
        if cache_alive < cache_file_mtime:
            log.info("Cache file less than 15 minutes")
            with open(cache_file, 'r') as skey_file:
                log.info("opening cache for read")
                if os.access(cache_file, 4):  # 4 - os.R_OK
                    return skey_file.read()
                else:
                    raise SystemExit("ERROR: Cannot read skey file '{c_skey}'".format(c_skey=cache_file))
    else:
        # Combine login and password to 'login_password' format.
        log.info("Generating login data")
        login_data = '_'.join([login, password])
        login_hash = md5(login_data.encode()).hexdigest()

        # Forming URL and trying to make GET query
        login_url = '{strg}/api/login/{hash}'.format(strg=storage, hash=login_hash)
        log.info("URL: {url}".format(url=login_url))

        # Processing XML
        log.info("calling query_xmlapi")
        return_code, response_message, xml_data = query_xmlapi(url=login_url, sessionkey=None)

        # 1 - success, write cache in file and return session key
        if return_code == '1':
            log.info("login successful")
            with open(cache_file, 'w') as skey_file:
                log.info("writing key to {file}".format(file=cache_file))
                skey_file.write("{skey}".format(skey=response_message))
            return response_message
        # 2 - Authentication Unsuccessful, return 2 as <str>
        elif return_code == '2':
            log.info("Error logging in")
            return return_code


def query_xmlapi(url, sessionkey):
    """
    Making HTTPS request to HP MSA XML API and returns it's response as 3-element tuple.
    :param url:
    URL to make GET request in <str>.
    :param sessionkey:
    Session key to authorize in <str>.
    :return:
    Tuple with return code <str>, return description <str> and etree object <xml.etree.ElementTree.Element>.
    """

    # Helps with debug info
    cur_fname = query_xmlapi.__name__

    # Makes GET request to URL
    try:
        url = 'https://' + url
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(url, headers={'sessionKey': sessionkey}, verify=False)
    except requests.exceptions.SSLError:
        raise SystemExit('ERROR: Cannot verify storage SSL Certificate.')
    except requests.exceptions.ConnectionError:
        raise SystemExit("ERROR: Cannot connect to storage.")

    # Reading data from server XML response
    try:
        response_xml = etree.fromstring(response.content)

        # Parse result XML to get return code and description
        return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
        return_response = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text

        # Placing all data to the tuple which will be returned
        return return_code, return_response, response_xml
    except (ValueError, AttributeError) as e:
        raise SystemExit("ERROR: {f} : Cannot parse XML. {exc}".format(f=cur_fname, exc=e))


def get_health(storage, sessionkey, component, item):
    """
    The function gets single item of MSA component. E.g. - status of one disk. It may be useful for Zabbix < 3.4.
    :param storage:
    String with storage name in DNS or it's IP address.
    :param sessionkey:
    String with session key, which must be attach to the request header.
    :param component:
    Name of storage component, what we want to get - vdisks, disks, etc.
    :param item:
    ID number of getting component - number of disk, name of vdisk, etc.
    :return:
    HTTP response text in XML format.
    """
    
    log.info("Starting function:  get_health")

    # Forming URL
    if component in ('controllers', 'enclosures', 'vdisks', 'disks'):
        get_url = '{strg}/api/show/{comp}'.format(strg=storage, comp=component)
    else:
        raise SystemExit('ERROR: Wrong component "{comp}"'.format(comp=component))
    log.info("URL: {url}".format(url=get_url))

    # Determine the path to store cache file
    tmp_dir = '/tmp/zbx-hpmsa-dev/'
    # Create temp dir if it's not exists
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
        # Making temp dir writable for zabbix user and group
        os.chmod(tmp_dir, 0o770)
    elif not os.access(tmp_dir, 2):  # 2 - os.W_OK:
        raise SystemExit("ERROR: '{tmp}' not writable for user ['{user}'].".format(tmp=tmp_dir,
                                                                                    user=os.getenv('USER')))
    else:
        # Current dir. Yeap, it's easier than getcwd() or os.path.dirname(os.path.abspath(__file__)).
        tmp_dir = ''

    log.info("temp dir: {tmp}".format(tmp=tmp_dir))
    
    # Cache file name
    cache_file = tmp_dir + 'zbx-hpmsa_{strg}.{comp}'.format(strg=storage, comp=component)
    log.info("cache_file: {cfile}".format(cfile=cache_file))

    # Trying to use cached session key
    pull_fresh=True
    if os.path.exists(cache_file):
        log.info("Cache file exists")
        cache_alive = datetime.utcnow() - timedelta(minutes=5)
        cache_file_mtime = datetime.utcfromtimestamp(os.path.getmtime(cache_file))
        log.info("Now: {now} / File: {mtime}".format(now=cache_alive,mtime=cache_file_mtime))

        if cache_alive < cache_file_mtime:
            log.info("Cache file less than 5 minutes")
            with open(cache_file, 'r') as data_file:
                log.info("opening cache for read")
                if os.access(cache_file, 4):  # 4 - os.R_OK
                    log.info("Access OK - Reading file")
                    pull_fresh=False
                    resp_return_code = 0
                    resp_xml = etree.fromstring(data_file.read())
                else:
                    raise SystemExit("ERROR: Cannot read {comp} file '{c_skey}'".format(comp=component, c_skey=cache_file))

    if pull_fresh:
        log.info("Pulling fresh data")
        # Making request to API
        resp_return_code, resp_description, resp_xml = query_xmlapi(get_url, sessionkey)
        if resp_return_code != '0':
            raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))
        else: 
            log.info("Valid data returned")
            tree = etree.ElementTree(resp_xml)
            log.info("saving data to file")
            tree.write(cache_file, pretty_print=True)
            #with open(cache_file, 'w') as data_file:
            #    data_file.write("{xml}".format(xml=etree.tostring(resp_xml, pretty_print=True)))

    # Matching dict
    comp_dict = {'controllers': 'controllers', 'enclosures': 'enclosures', 'vdisks': 'virtual-disk', 'disks': 'drive'}
    item_dict = {'controllers': 'controller-id', 'enclosures': 'enclosure-id', 'vdisks': 'name', 'disks': 'location'}
    # md = {'controllers': 'controller-id', 'enclosures': 'enclosure-id', 'vdisks': 'virtual-disk', 'disks': 'drive'}
    # Returns health statuses
    # disks and vdisks
    try:
        health_dict = {}
        for all_comp in resp_xml.findall("./OBJECT[@name='{comp}']".format(comp=comp_dict[component])):
            comp_id = all_comp.find("./PROPERTY[@name='{nd}']".format(nd=item_dict[component])).text
            # Add 'health' to dict
            health_dict[comp_id] = all_comp.find("./PROPERTY[@name='health-numeric']").text
        # If given item presents in our dict - return status
        if item in health_dict:
            health = health_dict[item]
        else:
            raise SystemExit("ERROR: No such id: '{item}'".format(item=item))
    else:
        raise SystemExit("ERROR: Wrong component '{comp}'".format(comp=component))
    return health


def make_discovery(storage, sessionkey, component):
    """
    :param storage:
    String with storage name in DNS or it's IP address.
    :param sessionkey:
    String with session key, which must be attach to the request header.
    :param component:
    Name of storage component, what we want to get - vdisks, disks, etc.
    :return:
    JSON with discovery data.
    """

    # Forming URL
    show_url = '{strg}/api/show/{comp}'.format(strg=storage, comp=component)

    # Making request to API
    resp_return_code, resp_description, xml = query_xmlapi(show_url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # Eject XML from response
    if component is not None:
        all_components = []
        raw_json_part = ''
        if component.lower() == 'vdisks':
            for vdisk in xml.findall("./OBJECT[@name='virtual-disk']"):
                vdisk_name = vdisk.find("./PROPERTY[@name='name']").text
                vdisk_dict = {"{#VDISKNAME}": "{name}".format(name=vdisk_name)}
                all_components.append(vdisk_dict)
        elif component.lower() == 'disks':
            for disk in xml.findall("./OBJECT[@name='drive']"):
                disk_loc = disk.find("./PROPERTY[@name='location']").text
                disk_sn = disk.find("./PROPERTY[@name='serial-number']").text
                disk_dict = {"{#DISKLOCATION}": "{loc}".format(loc=disk_loc),
                             "{#DISKSN}": "{sn}".format(sn=disk_sn)}
                all_components.append(disk_dict)
        elif component.lower() == 'controllers':
            for ctrl in xml.findall("./OBJECT[@name='controllers']"):
                ctrl_id = ctrl.find("./PROPERTY[@name='controller-id']").text
                ctrl_sn = ctrl.find("./PROPERTY[@name='serial-number']").text
                ctrl_ip = ctrl.find("./PROPERTY[@name='ip-address']").text
                #all_ports = [port.find("./PROPERTY[@name='port']").text
                #             for port in ctrl.findall("./OBJECT[@name='ports']")]
                #for port in all_ports:
                #    raw_json_part += '{{"{{#PORTNAME}}":"{}"}},'.format(port)
                # Forming final dict
                ctrl_dict = {"{#CTRLID}": "{id}".format(id=ctrl_id),
                             "{#CTRLSN}": "{sn}".format(sn=ctrl_sn),
                             "{#CTRLIP}": "{ip}".format(ip=ctrl_ip)}
                all_components.append(ctrl_dict)
        elif component.lower() == 'enclosures':
            for encl in xml.findall(".OBJECT[@name='enclosures']"):
                encl_id = encl.find("./PROPERTY[@name='enclosure-id']").text
                encl_sn = encl.find("./PROPERTY[@name='midplane-serial-number']").text
                #all_ps = [PS.find("./PROPERTY[@name='durable-id']").text
                #          for PS in encl.findall("./OBJECT[@name='power-supplies']")]
                #for ps in all_ps:
                #    raw_json_part += '{{"{{#POWERSUPPLY}}":"{}"}},'.format(ps)
                # Forming final dict
                encl_dict = {"{#ENCLOSUREID}": "{id}".format(id=encl_id),
                             "{#ENCLOSURESN}": "{sn}".format(sn=encl_sn)}
                all_components.append(encl_dict)

        # Dumps JSON and return it
        if not raw_json_part:
            return json.dumps({"data": all_components}, separators=(',', ':'))
        else:
            return json.dumps({"data": all_components}, separators=(',', ':'))[:-2] + ',' + raw_json_part[:-1] + ']}'
    else:
        raise SystemExit('ERROR: You must provide the storage component (vdisks, disks, controllers, enclosures)')


def get_all(storage, sessionkey, component):
    """
    :param storage:
    String with storage name in DNS or it's IP address.
    :param sessionkey:
    String with session key, which must be attach to the request header.
    :param component:
    Name of storage component, what we want to get - vdisks, disks, etc.
    :return:
    JSON with all found data. For example:
    Disks:
    {"1.1": { "health": "OK", "temperature": 25, "work_hours": 1234}, "1.2": { ... }}
    Vdisks:
    {"vdisk01": { "health": "OK" }, vdisk02: {"health": "OK"} }
    """

    get_url = '{strg}/api/show/{comp}/'.format(strg=storage, comp=component)

    # Making request to API
    resp_return_code, resp_description, xml = query_xmlapi(get_url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # Processing XML if response code 0
    all_components = {}
    if component == 'disks':
        for PROP in xml.findall("./OBJECT[@name='drive']"):
            # Getting data from XML
            disk_location = PROP.find("./PROPERTY[@name='location']").text
            disk_health = PROP.find("./PROPERTY[@name='health-numeric']").text
            disk_temp = PROP.find("./PROPERTY[@name='temperature-numeric']").text
            disk_work_hours = PROP.find("./PROPERTY[@name='power-on-hours']").text
            # Making dict with one disk data
            disk_info = {
                    "health": disk_health,
                    "temperature": disk_temp,
                    "work_hours": disk_work_hours
            }
            # Adding one disk to common dict
            all_components[disk_location] = disk_info
    elif component == 'vdisks':
        for PROP in xml.findall("./OBJECT[@name='virtual-disk']"):
            # Getting data from XML
            vdisk_name = PROP.find("./PROPERTY[@name='name']").text
            vdisk_health = PROP.find("./PROPERTY[@name='health-numeric']").text

            # Making dict with one vdisk data
            vdisk_info = {
                    "health": vdisk_health
            }
            # Adding one vdisk to common dict
            all_components[vdisk_name] = vdisk_info
    elif component == 'controllers':
        for PROP in xml.findall("./OBJECT[@name='controllers']"):
            # Getting data from XML
            ctrl_id = PROP.find("./PROPERTY[@name='controller-id']").text
            ctrl_health = PROP.find("./PROPERTY[@name='health-numeric']").text
            cf_health = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='health-numeric']").text
            # Getting info for all FC ports
            ports_info = {}
            for FC_PORT in PROP.findall("./OBJECT[@name='ports']"):
                port_name = FC_PORT.find("./PROPERTY[@name='port']").text
                port_health = FC_PORT.find("./PROPERTY[@name='health-numeric']").text
                port_status = FC_PORT.find("./PROPERTY[@name='status']").text
                sfp_status = FC_PORT.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-status']").text
                # Puts all info into dict
                ports_info[port_name] = {
                    "health": port_health,
                    "status": port_status,
                    "sfp_status": sfp_status
                }
                # Making final dict with info of the one controller
                ctrl_info = {
                    "health": ctrl_health,
                    "cf_health": cf_health,
                    "ports": ports_info
                }
                all_components[ctrl_id] = ctrl_info
    elif component == 'enclosures':
        for PROP in xml.findall("./OBJECT[@name='enclosures']"):
            encl_id = PROP.find("./PROPERTY[@name='enclosure-id']").text
            encl_health = PROP.find("./PROPERTY[@name='health-numeric']").text
            encl_status = PROP.find("./PROPERTY[@name='status']").text
            # Power supply info
            ps_info = {}
            for PS in PROP.findall("./OBJECT[@name='power-supplies']"):
                ps_id = PS.find("./PROPERTY[@name='durable-id']").text
                ps_name = PS.find("./PROPERTY[@name='name']").text
                ps_health = PS.find("./PROPERTY[@name='health-numeric']").text
                ps_status = PS.find("./PROPERTY[@name='status']").text
                ps_temp = PS.find("./PROPERTY[@name='dctemp']").text
                # Puts all info into dict
                ps_info[ps_id] = {
                    "name": ps_name,
                    "health": ps_health,
                    "status": ps_status,
                    "temperature": ps_temp
                }
                # Making final dict with info of the one controller
                encl_info = {
                    "health": encl_health,
                    "status": encl_status,
                    "power_supplies": ps_info
                }
                all_components[encl_id] = encl_info
    else:
        raise SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers)')
    # Making JSON with dumps() and return it (separators needs to make JSON compact)
    return json.dumps(all_components, separators=(',', ':'))


if __name__ == '__main__':
    # Current program version
    VERSION = '0.3.4'

    # Parse all given arguments
    parser = ArgumentParser(description='Zabbix module for HP MSA XML API.', add_help=True)
    parser.add_argument('-d', '--discovery', action='store_true', help='Making discovery')
    parser.add_argument('-g', '--get', type=str, help='ID of MSA part which status we want to get',
                        metavar='[DISKID|VDISKNAME|CONTROLLERID|ENCLOSUREID|all]')
    parser.add_argument('-u', '--user', default='monitor', type=str, help='User name to login in MSA')
    parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for your user')
    parser.add_argument('-m', '--msa', type=str, help='DNS name or IP address of your MSA controller',
                        metavar='[IP|DNSNAME]')
    parser.add_argument('-c', '--component', type=str, choices=['disks', 'vdisks', 'controllers', 'enclosures'],
                        help='MSA component for monitor or discover',
                        metavar='[disks|vdisks|controllers|enclosures]')
    parser.add_argument('--verbose', default=False, help='Log Verbose Output')
    parser.add_argument('-v', '--version', action='version', version=VERSION, help='Print the script version and exit')
    args = parser.parse_args()

    if args.verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)

    # Make no possible to use '--discovery' and '--get' options together
    if args.discovery and args.get:
        raise SystemExit("Syntax error: Cannot use '-d|--discovery' and '-g|--get' options together.")

    # Set msa_connect - IP or DNS name and determine to use https or not
    msa_connect = gethostbyname(args.msa)

    # Make no possible to use '--discovery' and '--get' options together
    if args.discovery and args.get:
        raise SystemExit("Syntax error: Cannot use '-d|--discovery' and '-g|--get' options together.")

    # Getting session key
    skey = get_skey(storage=msa_connect, login=args.user, password=args.password)

    if skey != '2':
        # If gets '--discovery' argument, make discovery
        if args.discovery:
            print(make_discovery(msa_connect, skey, args.component))
        # If gets '--get' argument, getting component's health
        elif args.get and args.get != 'all':
            print(get_health(msa_connect, skey, args.component, args.get))
        # Making bulk request for all possible component statuses
        elif args.get == 'all':
            print(get_all(msa_connect, skey, args.component))
        else:
            raise SystemExit("Syntax error: You must use '--discovery' or '--get' option anyway.")
    else:
        raise SystemExit('ERROR: Login or password is incorrect.')
