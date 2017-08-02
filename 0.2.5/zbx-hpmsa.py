#!/usr/bin/env python3

import xml.etree.ElementTree as eTree
from sys import exc_info
from hashlib import md5
from urllib import request
from urllib.error import URLError
from argparse import ArgumentParser
from json import dumps


def get_skey(storage, login, password):
    """
    :param storage:
    String with storage name in DNS or it's IP address.
    :param login:
    String with MSA username.
    :param password:
    String with MSA password.
    :return:
    Session key as string.
    """

    # Helps with debug info
    cur_fname = get_skey.__name__

    # Combine login and password to 'login_password' format.
    login_data = '_'.join([login, password])
    login_hash = md5(login_data.encode()).hexdigest()
    login_url = 'http://{0}/api/login/{1}'.format(storage, login_hash)
    # Trying to make HTTP request
    try:
        query = request.urlopen(login_url)
    except URLError:
        exc_value = exc_info()[1]
        if exc_value.reason.errno == 11001:
            raise SystemExit('ERROR: ({func}) Cannot open URL {url}'.format(func=cur_fname, url=login_url))
        else:
            raise SystemExit('ERROR: ({func}), {reason}'.format(func=cur_fname, reason=exc_value.reason))
    response = query.read()
    response_xml = eTree.fromstring(response.decode())
    response_return_code = response_xml.findall(".//OBJECT[@name='status']/PROPERTY[@name='return-code']")[0].text
    response_message = response_xml.findall(".//OBJECT[@name='status']/PROPERTY[@name='response']")[0].text

    if response_return_code == '2':
        return response_return_code
    elif response_return_code == '1':
        return response_message


def get_value(storage, sessionkey, component, item):
    """
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

    # Helps with debug info
    cur_fname = get_value.__name__

    if component in ['vdisks', 'disks']:
        get_url = 'http://{0}/api/show/{1}/{2}'.format(storage, component, item)
    elif component == 'controllers':
        get_url = 'http://{0}/api/show/{1}'.format(storage, component)
    else:
        return SystemExit('ERROR: Wrong component')
    req = request.Request(get_url)
    req.add_header('sessionKey', sessionkey)
    # Trying to make HTTP request
    try:
        query = request.urlopen(req)
    except URLError:
        exc_value = exc_info()[1]
        if exc_value.reason.errno == 11001:
            raise SystemExit('ERROR: ({func}) Cannot open URL: {url}'.format(func=cur_fname, url=get_url))
        else:
            raise SystemExit('ERROR: ({func}), {reason}'.format(func=cur_fname, reason=exc_value.reason))
    response = query.read()
    response_xml = eTree.fromstring(response.decode())
    response_return_code = response_xml.findall("./OBJECT[@name='status']/PROPERTY[@name='return-code']")[0].text
    response_description = response_xml.findall("./OBJECT[@name='status']/PROPERTY[@name='response']")[0].text

    # If return code is not 0, return response description message
    if int(response_return_code) != 0:
        SystemExit("ERROR: {0}".format(response_description))

    # Returns statuses
    # vsisks
    if component == 'vdisks':
        stat_arr = response_xml.findall("./OBJECT[@name='virtual-disk']/PROPERTY[@name='health']")
        if len(stat_arr) == 1:
            return stat_arr[0].text
        else:
            return "ERROR: ({0}) response handle error.".format(cur_fname)
    # disks
    elif component == 'disks':
        stat_arr = response_xml.findall("./OBJECT[@name='drive']/PROPERTY[@name='health']")
        if len(stat_arr) == 1:
            return stat_arr[0].text
        else:
            return "ERROR: ({0}) response handle error.".format(cur_fname)
    # controllers
    elif component == 'controllers':
        # we'll make dict {ctrl_id: health} because of we cannot call API for exact controller status, only all of them
        health_dict = {}
        for ctrl in response_xml.findall("./OBJECT[@name='controllers']"):
            # If length of item eq 1 symbols - it should be ID
            if len(item) == 1:
                ctrl_id = ctrl.findall("./PROPERTY[@name='controller-id']")[0].text
            # serial number, I think. Maybe I should add possibility to search controller by IP?..
            else:
                ctrl_id = ctrl.findall("./PROPERTY[@name='serial-number']")[0].text
            ctrl_health = ctrl.findall("./PROPERTY[@name='health']")[0].text
            health_dict[ctrl_id] = ctrl_health
        # If given item in our dict - return status
        if item in health_dict:
            return health_dict[item]
        else:
            return 'ERROR: No such controller ({0}). Found only these: {1}'.format(item, health_dict)
    # I know, we can't get anything else because of using 'choices' in argparse, but why not return something?..
    else:
        return 'Wrong component: {cmp}'.format(cmp=component)


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

    show_url = 'http://{0}/api/show/{1}'.format(storage, component)
    req = request.Request(show_url)
    req.add_header('sessionKey', sessionkey)
    # Trying to make HTTP request
    try:
        query = request.urlopen(req)
    except URLError:  # cannot open url
        exc_value = exc_info()[1]
        if exc_value.reason.errno == 11001:
            raise SystemExit('ERROR: ({func}) Cannot open URL: {url}'.format(func=cur_fname, url=show_url))
        else:
            raise SystemExit('ERROR: ({func}), {reason}'.format(func=cur_fname, reason=exc_value.reason))
    # Eject XML from response
    response = query.read()
    if len(response) != 0:
        xml_data = eTree.fromstring(response.decode())
    else:
        raise SystemExit('ERROR: ({func}) Got zero-length XML result'.format(func=cur_fname))
    if component is not None or len(component) != 0:
        all_components = []
        if component == 'vdisks':
            for vdisk in xml_data.findall("./OBJECT[@name='virtual-disk']"):
                vdisk_name = vdisk.findall("./PROPERTY[@name='name']")[0].text
                vdisk_dict = {"{#VDISKNAME}": "{name}".format(name=vdisk_name)}
                all_components.append(vdisk_dict)
        elif component == 'disks':
            for disk in xml_data.findall("./OBJECT[@name='drive']"):
                disk_loc = disk.findall("./PROPERTY[@name='location']")[0].text
                disk_sn = disk.findall("./PROPERTY[@name='serial-number']")[0].text
                disk_dict = {"{#DISKLOCATION}": "{loc}".format(loc=disk_loc),
                             "{#DISKSN}": "{sn}".format(sn=disk_sn)}
                all_components.append(disk_dict)
        elif component == 'controllers':
            for ctrl in xml_data.findall("./OBJECT[@name='controllers']"):
                ctrl_id = ctrl.findall("./PROPERTY[@name='controller-id']")[0].text
                ctrl_sn = ctrl.findall("./PROPERTY[@name='serial-number']")[0].text
                ctrl_ip = ctrl.findall("./PROPERTY[@name='ip-address']")[0].text
                ctrl_dict = {"{#CTRLID}": "{id}".format(id=ctrl_id),
                             "{#CTRLSN}": "{sn}".format(sn=ctrl_sn),
                             "{#CTRLIP}": "{ip}".format(ip=ctrl_ip)}
                all_components.append(ctrl_dict)
        to_json = {"data": all_components}
        return dumps(to_json, separators=(',', ':'))
    else:
        SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers)')


if __name__ == '__main__':
    # Current program version
    VERSION = '0.2.5'

    # Parse all given arguments
    parser = ArgumentParser(description='Zabbix module for MSA XML API.', add_help=True)
    parser.add_argument('-d', '--discovery', action='store_true')
    parser.add_argument('-g', '--get', type=str, help='ID of part which status we want to get',
                        metavar='<DISKID|VDISKNAME|CONTROLLERID|CONTROLLERSN>')
    parser.add_argument('-u', '--user', default='monitor', type=str, help='User name to login in MSA')
    parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for your user')
    parser.add_argument('-m', '--msa', type=str, help='DNS name or IP address of your MSA controller',
                        metavar='<IP> or <DNSNAME>')
    parser.add_argument('-c', '--component', type=str, choices=['disks', 'vdisks', 'controllers'],
                        help='MSA component to monitor',
                        metavar='<disks>,<vdisks>,<controllers>')
    parser.add_argument('-v', '--version', action='version', version=VERSION, help='Just show program version')
    args = parser.parse_args()

    skey = get_skey(args.msa, args.user, args.password)
    if skey == "2":
        raise SystemExit('ERROR: Login or password is incorrect.')
    # Parsing arguments
    # Make no possible to use '-d' and '-g' options together
    if args.discovery is True and args.get is not None:
        raise SystemExit("ERROR: Use cannot use both '--discovery' and '--get' options.")
    # If gets '--discovery' argument, make discovery
    elif args.discovery is True:
        print(make_discovery(args.msa, skey, args.component))
    # If gets '--get' argument, getting value of component
    elif args.get is not None and len(args.get) != 0:
        print(get_value(args.msa, skey, args.component, args.get))
    else:
        raise SystemExit("Usage Error: You must use '--discovery' or '--get' option anyway.")
