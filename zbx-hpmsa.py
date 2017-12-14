#!/usr/bin/env python3

from lxml import etree
from os import path, makedirs, name
from datetime import datetime, timedelta
from hashlib import md5
from argparse import ArgumentParser
from json import dumps
from socket import gethostbyname
from requests import get as req_get
from requests.exceptions import ConnectionError


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

    # Helps with debug info
    cur_fname = get_skey.__name__

    # Determine the path to store cache skey file
    if name == 'posix':
        tmp = '/tmp/zbx-hpmsa/'
    else:
        tmp = ''

    # Create temp dir if it's not exists
    if not path.exists(tmp) and tmp != '':
        try:
            makedirs(tmp)
        except FileNotFoundError as e:
            raise SystemExit("ERROR: Cannot create temp directory: {tmp}. {exc}".format(tmp=tmp, exc=e))
    # Cache file name
    cache_file = '{temp_dir}zbx-hpmsa_{str}.skey'.format(temp_dir=tmp, str=storage)

    # Trying to use cached session key
    if use_cache is True and path.exists(cache_file):
        cache_alive = datetime.utcnow() - timedelta(minutes=15)
        cache_file_mtime = datetime.utcfromtimestamp(path.getmtime(cache_file))
        if cache_alive < cache_file_mtime:
            with open(cache_file, 'r') as skey_file:
                return skey_file.read()
        else:
            return get_skey(storage, login, password, use_cache=False)
    else:
        # Combine login and password to 'login_password' format.
        login_data = '_'.join([login, password])
        login_hash = md5(login_data.encode()).hexdigest()
        # Forming URL to get auth token
        login_url = 'http://{str}/api/login/{hash}'.format(str=storage, hash=login_hash)
        # Trying to make GET query
        try:
            rsp_content = req_get(login_url).content

            # Processing XML
            xml_data = etree.fromstring(rsp_content)
            return_code = xml_data.find(".//PROPERTY[@name='return-code']").text
            response_message = xml_data.find(".//PROPERTY[@name='response']").text

            # 1 - success, return session key
            if return_code == '1':
                with open(cache_file, 'w') as skey_file:
                    skey_file.write("{skey}".format(skey=response_message))
                return response_message
            # 2 - Authentication Unsuccessful, return 2 as <str>
            elif return_code == '2':
                return return_code
        except ConnectionError:
            raise SystemExit('ERROR: ({f}) Could not connect to {url}'.format(f=cur_fname, url=login_url))


def query_xmlapi(url, sessionkey):
    """
    Making HTTP request to HP MSA XML API and returns it's response as 3-element tuple.
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
        response = req_get(url, headers={'sessionKey': sessionkey})
    except ConnectionError:
        raise SystemExit('ERROR: ({f}) Could not connect to {url}'.format(f=cur_fname, url=url))

    # Reading data from server response
    try:
        response_xml = etree.fromstring(response.content)

        # Parse result XML to get return code and description
        return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
        description = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text

        # Placing all data to the tuple which will be returned
        return_tuple = (return_code, description, response_xml)
        return return_tuple
    except ValueError as e:
        raise SystemExit("ERROR: {f} : Cannot parse XML. {exc}".format(f=cur_fname, exc=e))
    except AttributeError as e:
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

    # Helps with forming debug info
    cur_fname = get_health.__name__

    # Forming URL
    if component in ('vdisks', 'disks'):
        get_url = 'http://{strg}/api/show/{comp}/{item}'.format(strg=storage, comp=component, item=item)
    elif component in ('controllers', 'enclosures'):
        get_url = 'http://{strg}/api/show/{comp}'.format(strg=storage, comp=component)
    else:
        raise SystemExit('ERROR: Wrong component "{comp}"'.format(comp=component))

    # Making HTTP request with last formed URL and session key from get_skey()
    response = query_xmlapi(get_url, sessionkey)

    if len(response) == 3:
        resp_return_code, resp_description, resp_xml = response
    else:
        raise SystemExit("ERROR: ({f}) XML handle error".format(f=cur_fname))

    # Matching dict
    md = {'controllers': 'controller-id', 'enclosures': 'enclosure-id', 'vdisks': 'virtual-disk', 'disks': 'drive'}
    # Returns health statuses
    # disks and vdisks
    if component in ('vdisks', 'disks'):
        try:
            health = resp_xml.find("./OBJECT[@name='{nd}']/PROPERTY[@name='health']".format(nd=md[component])).text
        except AttributeError:
            raise SystemExit("ERROR: No such id: '{item}'".format(item=item))
    # controllers and enclosures
    elif component in ('controllers', 'enclosures'):
        # we'll make dict {ctrl_id: health} because of we cannot call API for exact controller status
        health_dict = {}
        for ctrl in resp_xml.findall("./OBJECT[@name='{comp}']".format(comp=component)):
            ctrl_id = ctrl.find("./PROPERTY[@name='{nd}']".format(nd=md[component])).text
            # Add 'health' to dict
            health_dict[ctrl_id] = ctrl.find("./PROPERTY[@name='health']").text
        # If given item presents in our dict - return status
        if item in health_dict:
            health = health_dict[item]
        else:
            raise SystemExit("ERROR: No such id: '{item}'.".format(item=item))
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

    # Helps with debug info
    cur_fname = make_discovery.__name__

    # Forming URL
    show_url = 'http://{strg}/api/show/{comp}'.format(strg=storage, comp=component)

    # Making HTTP request to pull needed data
    response = query_xmlapi(show_url, sessionkey)
    # If we've got 3 element tuple it's OK
    if len(response) == 3:
        resp_return_code, resp_description, resp_xml = response
    else:
        raise SystemExit("ERROR: ({f}) XML handle error".format(f=cur_fname))

    if resp_return_code != '0':
        raise SystemExit("ERROR: {rd}".format(rd=resp_description))

    # Eject XML from response
    if component is not None or len(component) != 0:
        all_components = []
        if component.lower() == 'vdisks':
            for vdisk in resp_xml.findall("./OBJECT[@name='virtual-disk']"):
                vdisk_name = vdisk.find("./PROPERTY[@name='name']").text
                vdisk_dict = {"{#VDISKNAME}": "{name}".format(name=vdisk_name)}
                all_components.append(vdisk_dict)
        elif component.lower() == 'disks':
            for disk in resp_xml.findall("./OBJECT[@name='drive']"):
                disk_loc = disk.find("./PROPERTY[@name='location']").text
                disk_sn = disk.find("./PROPERTY[@name='serial-number']").text
                disk_dict = {"{#DISKLOCATION}": "{loc}".format(loc=disk_loc),
                             "{#DISKSN}": "{sn}".format(sn=disk_sn)}
                all_components.append(disk_dict)
        elif component.lower() == 'controllers':
            for ctrl in resp_xml.findall("./OBJECT[@name='controllers']"):
                ctrl_id = ctrl.find("./PROPERTY[@name='controller-id']").text
                ctrl_sn = ctrl.find("./PROPERTY[@name='serial-number']").text
                ctrl_ip = ctrl.find("./PROPERTY[@name='ip-address']").text
                ctrl_dict = {"{#CTRLID}": "{id}".format(id=ctrl_id),
                             "{#CTRLSN}": "{sn}".format(sn=ctrl_sn),
                             "{#CTRLIP}": "{ip}".format(ip=ctrl_ip)}
                all_components.append(ctrl_dict)
        elif component.lower() == 'enclosures':
            for encl in resp_xml.findall(".OBJECT[@name='enclosures']"):
                encl_id = encl.find("./PROPERTY[@name='enclosure-id']").text
                encl_sn = encl.find("./PROPERTY[@name='midplane-serial-number']").text
                encl_dict = {"{#ENCLOSUREID}": "{id}".format(id=encl_id),
                             "{#ENCLOSURESN}": "{sn}".format(sn=encl_sn)}
                all_components.append(encl_dict)
        to_json = {"data": all_components}
        return dumps(to_json, separators=(',', ':'))
    else:
        raise SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers, enclosures)')


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

    # Helps with forming debug info
    cur_fname = get_all.__name__

    get_url = 'http://{strg}/api/show/{comp}/'.format(strg=storage, comp=component)
    # Trying to open the url
    response = query_xmlapi(get_url, sessionkey)

    # Processing XML if response code 0
    if response[0] == '0':
        xml = response[2]
        all_components = {}
        if component == 'disks':
            for PROP in xml.findall("OBJECT[@name='drive']"):
                # Getting data from XML
                disk_location = PROP.find("PROPERTY[@name='location']").text
                disk_health = PROP.find("PROPERTY[@name='health']").text
                disk_temp = PROP.find("PROPERTY[@name='temperature-numeric']").text
                disk_work_hours = PROP.find("PROPERTY[@name='power-on-hours']").text
                # Making dict with one disk data
                disk_info = {
                        "health": disk_health,
                        "temperature": disk_temp,
                        "work_hours": disk_work_hours
                }
                # Adding one disk to common dict
                all_components[disk_location] = disk_info
        elif component == 'vdisks':
            for PROP in xml.findall("OBJECT[@name='virtual-disk']"):
                # Getting data from XML
                vdisk_name = PROP.find("PROPERTY[@name='name']").text
                vdisk_health = PROP.find("PROPERTY[@name='health']").text

                # Making dict with one vdisk data
                vdisk_info = {
                        "health": vdisk_health
                }
                # Adding one vdisk to common dict
                all_components[vdisk_name] = vdisk_info
        elif component == 'controllers':
            for PROP in xml.findall("OBJECT[@name='controllers']"):
                # Getting data from XML
                ctrl_id = PROP.find("PROPERTY[@name='controller-id']").text
                ctrl_health = PROP.find("PROPERTY[@name='health']").text
                cf_health = PROP.find("OBJECT[@basetype='compact-flash']/PROPERTY[@name='health']").text
                # Getting info for all FC ports
                ports_info = {}
                for FC_PORT in PROP.findall("OBJECT[@name='ports']"):
                    port_name = FC_PORT.find("PROPERTY[@name='port']").text
                    port_health = FC_PORT.find("PROPERTY[@name='health']").text
                    port_status = FC_PORT.find("PROPERTY[@name='status']").text
                    sfp_status = FC_PORT.find("OBJECT[@name='port-details']/PROPERTY[@name='sfp-status']").text
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
        else:
            raise SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers)')
        # Making JSON with dumps() and return it (separators needs to make JSON compact)
        return dumps(all_components, separators=(',', ':'))
    else:
        raise SystemExit("ERROR: ({f}) : Response code from API is {rc} ({rm})".format(f=cur_fname, rc=response[0],
                                                                                       rm=response[1]))


if __name__ == '__main__':
    # Current program version
    VERSION = '0.3.1'

    # Parse all given arguments
    parser = ArgumentParser(description='Zabbix module for HP MSA XML API.', add_help=True)
    parser.add_argument('-d', '--discovery', action='store_true')
    parser.add_argument('-g', '--get', type=str, help='ID of MSA part which status we want to get',
                        metavar='<DISKID>|<VDISKNAME>|<CONTROLLERID>|<ENCLOSUREID>|all')
    parser.add_argument('-u', '--user', default='monitor', type=str, help='User name to login in MSA')
    parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for your user')
    parser.add_argument('-m', '--msa', type=str, help='DNS name or IP address of your MSA controller',
                        metavar='[<IP>|<DNSNAME>]')
    parser.add_argument('-c', '--component', type=str, choices=['disks', 'vdisks', 'controllers', 'enclosures'],
                        help='MSA component for monitor or discover',
                        metavar='[disks|vdisks|controllers|enclosures]')
    parser.add_argument('-v', '--version', action='version', version=VERSION, help='Print the script version and exit')
    args = parser.parse_args()

    # Define MSA Controller IP address (useful, if we have 2-ctrl configuration)
    if args.msa:
        msa_ip = gethostbyname(args.msa)
    else:
        raise SystemExit("ERROR: Missed mandatory argument '-m|--msa'.")

    # Getting session key
    skey = get_skey(storage=msa_ip, login=args.user, password=args.password, use_cache=True)

    if skey != '2':
        # Make no possible to use '--discovery' and '--get' options together
        if args.discovery is True and args.get is not None:
            raise SystemExit("ERROR: You cannot use both '--discovery' and '--get' options.")

        # If gets '--discovery' argument, make discovery
        elif args.discovery is True:
            print(make_discovery(msa_ip, skey, args.component))
        # If gets '--get' argument, getting component's health
        elif args.get is not None and len(args.get) != 0 and args.get != 'all':
            print(get_health(msa_ip, skey, args.component, args.get))
        # Making bulk request for all possible component statuses
        elif args.get == 'all':
            print(get_all(msa_ip, skey, args.component))
        else:
            raise SystemExit("Syntax error: You must use '--discovery' or '--get' option anyway.")
    else:
        raise SystemExit('ERROR: Login or password is incorrect.')
