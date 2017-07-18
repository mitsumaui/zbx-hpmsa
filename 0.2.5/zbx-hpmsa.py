#!/bin/python3

import xml.etree.ElementTree as eTree
from sys import exc_info
from hashlib import md5
from urllib import request
from urllib.error import URLError
from re import sub
from argparse import ArgumentParser


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
    response_xml = eTree.fromstring(query.read().decode())
    session_key = response_xml.findall(".//OBJECT[@name='status']/PROPERTY[@name='response']")[0].text

    if len(session_key) != 0:
        return session_key
    else:
        raise SystemExit('ERROR: ({func}) Got zero-length value for session key'.format(func=cur_fname))


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
    # Return vdisk status
    if component == 'vdisks':
        stat_arr = response_xml.findall("./OBJECT[@name='virtual-disk']/PROPERTY[@name='health']")
        if len(stat_arr) == 1:
            return stat_arr[0].text
    # Return disk status
    elif component == 'disks':
        stat_arr = response_xml.findall("./OBJECT[@name='drive']/PROPERTY[@name='health']")
        if len(stat_arr) == 1:
            return stat_arr[0].text
    # Return controller status
    elif component == 'controllers':
        status_dict = {}
        for ctrl in response_xml.findall("./OBJECT[@name='controllers']"):
            if len(item) == 1:
                ctrl_id = ctrl.findall("./PROPERTY[@name='controller-id']")[0].text
            else:
                ctrl_id = ctrl.findall("./PROPERTY[@name='serial-number']")[0].text
            ctrl_health = ctrl.findall("./PROPERTY[@name='health']")[0].text
            status_dict[ctrl_id] = ctrl_health
        if item in status_dict:
            return status_dict[item]
        else:
            return 'ERROR: No such controller ({0})'.format(item)

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
    response_xml = query.read()
    if len(response_xml) != 0:
        discovery_xml = eTree.fromstring(response_xml.decode())
    else:
        raise SystemExit('ERROR: ({func}) Got zero-length XML result'.format(func=cur_fname))
    if component is not None or len(component) != 0:
        json_body = ''
        if component == 'vdisks':
            for vdisk in discovery_xml.findall("./OBJECT[@name='virtual-disk']"):
                vdisk_name = vdisk.findall("./PROPERTY[@name='name']")[0].text
                json_body += '{{"{{#VDISKNAME}}":"{name}"}},'.format(name=vdisk_name)
        elif component == 'disks':
            for disk in discovery_xml.findall("./OBJECT[@name='drive']"):
                disk_loc = disk.findall("./PROPERTY[@name='location']")[0].text
                disk_sn = disk.findall("./PROPERTY[@name='serial-number']")[0].text
                json_body += '{{"{{#DISKLOCATION}}":"{id}","{{#DISKSN}}":"{sn}"}},'.format(id=disk_loc, sn=disk_sn)
        elif component == 'controllers':
            for ctrl in discovery_xml.findall("./OBJECT[@name='controllers']"):
                ctrl_id = ctrl.findall("./PROPERTY[@name='controller-id']")[0].text
                ctrl_sn = ctrl.findall("./PROPERTY[@name='serial-number']")[0].text
                ctrl_ip = ctrl.findall("./PROPERTY[@name='ip-address']")[0].text
                json_body += '{{"{{#CTRLID}}":"{id}","{{#CTRLSN}}":"{sn}","{{#CTRLIP}}":"{ip}"}},'.format(
                    id=ctrl_id, sn=ctrl_sn, ip=ctrl_ip)
        json_body = sub(r',$', '', json_body)
        json_full = '{"data":[' + json_body + ']}'
        return json_full
    else:
        SystemExit('ERROR: You should provide the storage component (vdisks, disks).')


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
    if skey == 'Authentication Unsuccessful':
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
