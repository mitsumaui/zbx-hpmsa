#!/usr/bin/env python3

import xml.etree.ElementTree as eTree
from socket import gethostbyname
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
    Session key as <str> of error code as <str>
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
    return_code = response_xml.find(".//PROPERTY[@name='return-code']").text
    response_message = response_xml.find(".//PROPERTY[@name='response']").text

    if return_code == '2':  # 2 - Authentication Unsuccessful, return 2 as <str>
        return return_code
    elif return_code == '1':  # 1 - success, return session key
        return response_message


def make_httpreq(url, sessionkey):
    """
    :param url:
    URL to make GET request in <str>.
    :param sessionkey:
    Session key to authorize in <str>.
    :return:
    Tuple with return code <str>, return description <str> and eTree object <xml.etree.ElementTree.Element>.
    """

    # Helps with debug info
    cur_fname = get_value.__name__

    req = request.Request(url)
    # Create 'sessionkey' header with skey
    req.add_header('sessionKey', sessionkey)
    # Trying to open the url
    try:
        query = request.urlopen(req)
    except URLError:
        exc_value = exc_info()[1]
        if exc_value.reason.errno == 11001:
            raise SystemExit('ERROR: ({func}) Cannot open URL: {url}'.format(func=cur_fname, url=url))
        else:
            raise SystemExit('ERROR: ({func}), {reason}'.format(func=cur_fname, reason=exc_value.reason))
    # Reading data from server response
    response = query.read()
    response_xml = eTree.fromstring(response.decode())
    # Parse result XML to get return code and description
    return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
    description = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text
    # Placing all data to the tuple which will be returned
    return_tuple = (return_code, description, response_xml)
    return return_tuple


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

    # Forming URL
    if component in ['vdisks', 'disks']:
        get_url = 'http://{0}/api/show/{1}/{2}'.format(storage, component, item)
    elif component in ('controllers', 'enclosures'):
        get_url = 'http://{0}/api/show/{1}'.format(storage, component)
    else:
        raise SystemExit('ERROR: Wrong component "{0}"'.format(component))

    # Making HTTP request with last formed URL and session key from get_skey()
    response = make_httpreq(get_url, sessionkey)
    if len(response) == 3:
        resp_return_code, resp_description, resp_xml = response
    else:
        raise SystemExit("ERROR: ({0}) XML handle error".format(cur_fname))

    # Returns statuses
    # vsisks
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
    elif component == 'controllers':
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
        # If given item in our dict - return status
        if item in health_dict:
            return health_dict[item]
        else:
            return 'ERROR: No such controller ({0}). Found only these: {1}'.format(item, health_dict)
    elif component.lower() == 'enclosures':
        health_dict = {}
        for encl in resp_xml.findall("./OBJECT[@name='enclosures']"):
            # If length of item eq 1 symbols - it should be ID
            if len(item) == 1:
                encl_id = encl.find("./PROPERTY[@name='enclosure-id']").text
            # serial number, I think.
            else:
                encl_id = encl.find("./PROPERTY[@name='midplane-serial-number']").text
            encl_health = encl.find("./PROPERTY[@name='health']").text
            health_dict[encl_id] = encl_health
            # If given item presents in our dict - return status
        if item in health_dict:
            return health_dict[item]
        else:
            return "ERROR: No such enclosure '{item}'. Found only these: {hd}".format(item=item, hd=health_dict)
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

    # Forming URL
    show_url = 'http://{0}/api/show/{1}'.format(storage, component)

    # Making HTTP request to pull needed data
    response = make_httpreq(show_url, sessionkey)
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
        if component == 'vdisks':
            for vdisk in resp_xml.findall("./OBJECT[@name='virtual-disk']"):
                vdisk_name = vdisk.find("./PROPERTY[@name='name']").text
                vdisk_dict = {"{#VDISKNAME}": "{name}".format(name=vdisk_name)}
                all_components.append(vdisk_dict)
        elif component == 'disks':
            for disk in resp_xml.findall("./OBJECT[@name='drive']"):
                disk_loc = disk.find("./PROPERTY[@name='location']").text
                disk_sn = disk.find("./PROPERTY[@name='serial-number']").text
                disk_dict = {"{#DISKLOCATION}": "{loc}".format(loc=disk_loc),
                             "{#DISKSN}": "{sn}".format(sn=disk_sn)}
                all_components.append(disk_dict)
        elif component == 'controllers':
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
        SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers, enclosures)')


if __name__ == '__main__':
    # Current program version
    VERSION = '0.2.5.3'

    # Parse all given arguments
    parser = ArgumentParser(description='Zabbix module for MSA XML API.', add_help=True)
    parser.add_argument('-d', '--discovery', action='store_true')
    parser.add_argument('-g', '--get', type=str, help='ID of part which status we want to get',
                        metavar='<DISKID|VDISKNAME|CONTROLLERID|CONTROLLERSN>|<ENCLOSUREID>|<ENCLOSURESN>')
    parser.add_argument('-u', '--user', default='monitor', type=str, help='User name to login in MSA')
    parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for your user')
    parser.add_argument('-m', '--msa', type=str, help='DNS name or IP address of your MSA controller',
                        metavar='<IP> or <DNSNAME>')
    parser.add_argument('-c', '--component', type=str, choices=['disks', 'vdisks', 'controllers', 'enclosures'],
                        help='MSA component to monitor',
                        metavar='<disks>,<vdisks>,<controllers>,<enclosures>')
    parser.add_argument('-v', '--version', action='version', version=VERSION, help='Just show program version')
    args = parser.parse_args()

    # Determine MSA IP by hostname
    msa_ip = gethostbyname(args.msa)
    # Getting session key and check it
    skey = get_skey(msa_ip, args.user, args.password)
    if skey != '2':
        # Parsing arguments
        # Make no possible to use '-d' and '-g' options together
        if args.discovery is True and args.get is not None:
            raise SystemExit("ERROR: You cannot use both '--discovery' and '--get' options.")

        # If gets '--discovery' argument, make discovery
        elif args.discovery is True:
            print(make_discovery(msa_ip, skey, args.component))

        # If gets '--get' argument, getting value of component
        elif args.get is not None and len(args.get) != 0:
            print(get_value(msa_ip, skey, args.component, args.get))
        else:
            raise SystemExit("Usage Error: You must use '--discovery' or '--get' option anyway.")
    else:
        raise SystemExit('ERROR: Login or password is incorrect.')
