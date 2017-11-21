#!/usr/bin/env python3

import xml.etree.ElementTree as eTree
from hashlib import md5
from argparse import ArgumentParser
from json import dumps
import requests


def get_skey(storage, login, password):
    """
    Get's session key from HP MSA API.
    :param storage:
    String with storage name in DNS or it's IP address.
    :param login:
    String with MSA username.
    :param password:
    String with MSA password.
    :return:
    Session key as <str> or error code as <str>
    """

    # Helps with debug info
    cur_fname = get_skey.__name__

    # Combine login and password to 'login_password' format.
    login_data = '_'.join([login, password])
    login_hash = md5(login_data.encode()).hexdigest()
    # Forming URL to get auth token
    login_url = 'http://{0}/api/login/{1}'.format(storage, login_hash)
    # Trying to make GET query
    try:
        response = requests.get(login_url)
    except requests.exceptions.ConnectionError:
        raise SystemExit('ERROR: ({f}) Could not connect to {url}'.format(f=cur_fname, url=login_url))
    response_xml = eTree.fromstring(response.text)
    return_code = response_xml.find(".//PROPERTY[@name='return-code']").text
    response_message = response_xml.find(".//PROPERTY[@name='response']").text

    if return_code == '2':  # 2 - Authentication Unsuccessful, return 2 as <str>
        return return_code
    elif return_code == '1':  # 1 - success, return session key
        return response_message


def query_xmlapi(url, sessionkey):
    """
    Making HTTP request to HP MSA XML API and returns it's response as 3-element tuple.
    :param url:
    URL to make GET request in <str>.
    :param sessionkey:
    Session key to authorize in <str>.
    :return:
    Tuple with return code <str>, return description <str> and eTree object <xml.etree.ElementTree.Element>.
    """

    # Helps with debug info
    cur_fname = query_xmlapi.__name__

    try:
        response = requests.get(url, headers={'sessionKey': sessionkey})
    except requests.exceptions.ConnectionError:
        raise SystemExit('ERROR: ({f}) Could not connect to {url}'.format(f=cur_fname, url=url))
    # Reading data from server response
    response_xml = eTree.fromstring(response.text)
    # Parse result XML to get return code and description
    return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
    description = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text
    # Placing all data to the tuple which will be returned
    return_tuple = (return_code, description, response_xml)
    return return_tuple


def get_value(storage, sessionkey, component, item):
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
    cur_fname = get_value.__name__

    # Forming URL
    if component.lower() in ('vdisks', 'disks'):
        get_url = 'http://{strg}/api/show/{comp}/{item}'.format(strg=storage, comp=component, item=item)
    elif component.lower() == 'controllers':
        get_url = 'http://{strg}/api/show/{comp}'.format(strg=storage, comp=component)
    else:
        raise SystemExit('ERROR: Wrong component "{comp}"'.format(comp=component))

    # Making HTTP request with last formed URL and session key from get_skey()
    response = query_xmlapi(get_url, sessionkey)
    if len(response) == 3:
        resp_return_code, resp_description, resp_xml = response
    else:
        raise SystemExit("ERROR: ({f}) XML handle error".format(f=cur_fname))

    # If return code is not 0 make workaround of authentication problem - just trying one more time
    if int(resp_return_code) != 0:
        attempts = 0
        # Doing two attempts
        while int(resp_return_code) != 0 and attempts < 3:
            # Getting new session key
            sessionkey = get_skey(args.msa, args.user, args.password)
            # And making new request to the storage
            response = query_xmlapi(get_url, sessionkey)
            resp_return_code, resp_description, resp_xml = response
            attempts += 1

        if int(resp_return_code) != 0:
            raise SystemExit("ERROR: {rd}".format(rd=resp_description))

    # Returns statuses
    # vdisks
    if component.lower() == 'vdisks':
        vdisk_health = resp_xml.find("./OBJECT[@name='virtual-disk']/PROPERTY[@name='health']").text
        if len(vdisk_health) != 0:
            return vdisk_health
        else:
            return "ERROR: ({f}) response handle error.".format(f=cur_fname)
    # disks
    elif component.lower() == 'disks':
        disk_health = resp_xml.find("./OBJECT[@name='drive']/PROPERTY[@name='health']").text
        if len(disk_health) != 1:
            return disk_health
        else:
            return "ERROR: ({f}) response handle error.".format(f=cur_fname)
    # controllers
    elif component.lower() == 'controllers':
        # we'll make dict {ctrl_id: health} because of we cannot call API for exact controller status, only all of them
        health_dict = {}
        for ctrl in resp_xml.findall("./OBJECT[@name='controllers']"):
            # If length of item eq 1 symbols - it should be ID
            if len(item) == 1:
                ctrl_id = ctrl.find("./PROPERTY[@name='controller-id']").text
            # serial number, I think. Maybe I should add possibility to search controller by IP?..
            else:
                ctrl_id = ctrl.find("./PROPERTY[@name='serial-number']").text
            ctrl_health = ctrl.find("./PROPERTY[@name='health']").text
            health_dict[ctrl_id] = ctrl_health
        # If given item presents in our dict - return status
        if item in health_dict:
            return health_dict[item]
        else:
            return 'ERROR: No such controller ({item}). Found only these: {hd}'.format(item=item, hd=health_dict)
    # I know, we can't get anything else because of using 'choices' in argparse, but why not return something?..
    else:
        return 'Wrong component: {comp}'.format(comp=component)


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

    # Yeah, hell! Some shit workaround code here!
    if component.lower() == 'all':
        all_components = []
        for comp in ['disks', 'vdisks', 'controllers']:
            data = get_all(storage, sessionkey, comp)
            # print('Data from get_all:\n', data)
            # print('\n')
            if comp == 'disks':
                data_dict = {"{#ALL_DISKS}": data}
            elif comp == 'vdisks':
                data_dict = {"{#ALL_VDISKS}": data}
            elif comp == 'controllers':
                data_dict = {"{#ALL_CONTROLLERS}": data}
            else:
                raise SystemExit("ERROR: Wrong component - '{0}'".format(comp))
            all_components.append(data_dict)
        return {"data": all_components}

    # Forming URL
    show_url = 'http://{0}/api/show/{1}'.format(storage, component)

    # Making HTTP request to pull needed data
    response = query_xmlapi(show_url, sessionkey)
    # If we've got 3 element tuple it's OK
    if len(response) == 3:
        resp_return_code, resp_description, resp_xml = response
    else:
        raise SystemExit("ERROR: ({0}) XML handle error".format(cur_fname))

    if int(resp_return_code) != 0:
        raise SystemExit("ERROR: {0}".format(resp_description))

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
        to_json = {"data": all_components}
        return dumps(to_json, separators=(',', ':'))
    else:
        raise SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers)')


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
    try:
        response = requests.get(get_url, headers={'sessionKey': sessionkey})
    except requests.exceptions.ConnectionError:
        raise SystemExit('ERROR: ({f}) Could not connect to {url}'.format(f=cur_fname, url=get_url))

    if response.status_code == 200:
        # Making XML
        xml = eTree.fromstring(response.text)
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


if __name__ == '__main__':
    # Current program version
    VERSION = '0.3'

    # Parse all given arguments
    parser = ArgumentParser(description='Zabbix module for HP MSA XML API.', add_help=True)
    parser.add_argument('-d', '--discovery', action='store_true')
    parser.add_argument('-g', '--get', type=str, help='ID of part which status we want to get',
                        metavar='<DISKID>|<VDISKNAME>|<CONTROLLERID>|<CONTROLLERSN>|all')
    parser.add_argument('-u', '--user', default='monitor', type=str, help='User name to login in MSA')
    parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for your user')
    parser.add_argument('-m', '--msa', type=str, help='DNS name or IP address of your MSA controller',
                        metavar='[<IP>|<DNSNAME>]')
    parser.add_argument('-c', '--component', type=str, choices=['disks', 'vdisks', 'controllers', 'all'],
                        help='MSA component to monitor or discover',
                        metavar='[disks|vdisks|controllers]')
    parser.add_argument('-v', '--version', action='version', version=VERSION, help='Print the script version and exit')
    args = parser.parse_args()

    # Getting session key and check it
    skey = get_skey(args.msa, args.user, args.password)

    if skey != '2':
        # Parsing arguments
        # Make no possible to use '-d' and '-g' options together
        if args.discovery is True and args.get is not None:
            raise SystemExit("ERROR: You cannot use both '--discovery' and '--get' options.")

        # If gets '--discovery' argument, make discovery
        elif args.discovery is True:
            print(make_discovery(args.msa, skey, args.component))
        # If gets '--get' argument, getting value of component
        elif args.get is not None and len(args.get) != 0 and args.get != 'all':
            print(get_value(args.msa, skey, args.component, args.get))
        elif args.get == 'all':
            print(get_all(args.msa, skey, args.component))
        else:
            raise SystemExit("Syntax error: You must use '--discovery' or '--get' option anyway.")
    else:
        raise SystemExit('ERROR: Login or password is incorrect.')
