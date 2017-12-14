# zbx-hpmsa
Zabbix module for monitor HPE MSA storages via XML API.  
Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api  
Also you can contact me with vk.com and Telegram: https://vk.com/asand3r, @asand3r

**Latest stable version:** 0.3

## Dependencies
 - requests
 - lxml (experimental, may be replaced with 'xml' from Python stdlib)

zbx-hpmsa provides possibility to make LLD of physical and virtual disks on HP MSA storages via it's XML API. Also it can gets status of discovered component.  
Program wrote with Python 3.6.3, but works with Python 3.4 from CentOS (I didn't check it with earlier versions, sorry).  
Version 0.3 get same interface like v0.2, so it's compatible by arguments. Also it has the same arguments and can be use like v0.2, but now you must install 'requests' library first. Also, as experiment I'm using 'lxml' instead default 'xml' from standard Python library, so you should intstall it too for now.  
 - [x] Bulk requests for dependent items of Zabbix 3.4
 - [x] Enclosures monitoring
 - [x] Session key cache (MSA login cache)
 
**Feautres**

Low Level Discovery:
 - [x] physical disks 
 - [x] virtual disks
 - [x] controllers
 - [x] Enclosures

Component status:
 - [x] physical disks 
 - [x] virtual disks
 - [x] controllers
 - [x] Enclosures

## Usage
- Both 0.2 and 0.3 versions has LLD of controllers, vdisks and disks:
```bash
[user@server ~] # ./zbx-hpmsa.py --discovery --msa MSA-NAME-OR-IP --component vdisks

{"data":[{"{#VDISKNAME}":"vDisk01"},{"{#VDISKNAME}":"vDisk02"}]}
```
- Request health status of one component. E.g. disk 1.1:
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
Template will works both in 0.2 and 0.3 versions, also I'll add template with dependent items as soon as posible.  
Have fun and rate it on [share.zabbix.com](https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api) if you like it. =)

**Tested with**:  
HP MSA 2040

**Known Issues**:
- Sometimes appears the error "The user is not recognized on this system" though username and password are correct.
  - Think I've fixed it in 0.2.5.2 and higher.
