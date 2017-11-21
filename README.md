# zbx-hpmsa
Zabbix module to monitor HP MSA storages via XML API.
Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api
Also you can contact me with vk.com: https://vk.com/asand3r

For now it has two major versions - '0.2' and '0.3'. The first one developed for working with Zabbix 3.0-3.2 (maybe lower too, but I didn't check)
and it must makes two request to HP MSA API to get one value - one for authentication and one for getting data. Unfortunately, there is an important
limitation in that mechanism - we cannot get more metrics than one or two per HP MSA component without crashing the API. E.g. to get health status of
one disk you should make two requests. Let's suppose, you want to get temperature for the same disk too - it's plus two more requests to API.
Now, multiply it for 24 disks and feel the problem. People uses something like 'cache' as workaround - get all possible data with one request and put it
to a file, where from they send data to Zabbix. Luckily for me, when I found this problem Zabbix 3.4 has been released. =) So, I've developed new version
using [dependent items](https://www.zabbix.com/documentation/3.4/manual/config/items/itemtypes/dependent_items) functionality.

## Version 0.2
zbx-hpmsa provides possibility to make LLD of physical and virtual disks on HP MSA storages via it's XML API. Also it can gets status of discovered component.
Program wrote with Python 3.5.3, but works with Python 3.4 (I didn't check it with earlier versions, sorry) and doesn't depends of any external library.

**Latest stable version:** 0.2.5.2

**Feautres**

Low Level Discovery:
 - [x] physical disks 
 - [x] virtual disks
 - [x] controllers

Component status:
 - [x] physical disks 
 - [x] virtual disks
 - [x] controllers
 
 **TODO**
 - [ ] Enclosures monitoring
 
 ## Version 0.3 (dev)
 Version 0.3 get all features that 0.2 has. Also it has the same arguments and can be use like 0.2, but now you must install 'requests' library first.  
 - [x] Bulk requests for dependent items of Zabbix 3.4
 - [ ] Enclosures monitoring

## Usage
- Both 0.2 and 0.3 versions has LLD of controllers, vdisks and disks:
```bash
[user@server ~] # ./zbx-hpmsa.py --discovery --msa MSA-NAME-OR-IP --component vdisks

{"data":[{"{#VDISKNAME}":"vDisk01"},{"{#VDISKNAME}":"vDisk02"}]}
```
- Also, they can request health status of one component. E.g. disk 1.1:
```bash
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get 1.1

OK
```
- Version 0.3 can make bulk request to get all available data:
```bash
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get all
{"1.1":{"health":"OK","temperature":"25","work_hours":"21170"},"1.2":{"health":"OK","temperature":"24","work_hours":"21168"}, ...}
```

## Zabbix templates
In addition I've attached preconfigured Zabbix Template here, so you can use it in your environment. It's using Low Level Discovery functionality
and {HOST.CONN} macro to determine HTTP connection URL, so make sure that it points to right DNS name or IP. This template expects what your MSA storage
has default user with default password - 'monitor'/'!monitor', but if it isn't true - correct it with '-u' and '-p' options. You can check it it command line:
```bash
[user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get all --user FOO --password BAR
```
Template will works both in 0.2 and 0.3 versions, also I'll add template with dependent items soon.
Have fun and rate it on share.zabbix.com if you like it. =)

**Tested with**:  
HP MSA 2040

**Known Issues**:
- Sometimes appears the error "The user is not recognized on this system" though username and password are correct.
  - Think I've fixed it in 0.2.5.1. But it's may be not exactly. =) The 0.3 version shouldn't has this problem by design.
