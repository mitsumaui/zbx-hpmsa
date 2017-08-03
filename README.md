# zbx-hpmsa
Zabbix module to monitor HP MSA storages via XML API.  

Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api  
Also you can contact me with vk.com: https://vk.com/asand3r

zbx-hpmsa provides possibility to make LLD of physical and virtual disks on HP MSA storages via it's XML API. Also it can gets status of discovered component.
Program wrote with Python 3.5.3, but works with Python 3.4 (I didn't check it with earlier versions, sorry) and doesn't depends of any external library.

**Latest stable version:** 0.2.5.1  
**Latest testing version:** 0.2.6

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
 - Enclosures monitoring

**Usage**
  - LLD:
  ```bash
    [user@server ~] # ./zbx-hpmsa.py --discovery --msa MSA-NAME-OR-IP --component vdisks
    
    {"data":[{"{#VDISKNAME}":"vDisk01"},{"{#VDISKNAME}":"vDisk02"}]}
  ```
  - Component status:
  ```bash
    [user@server ~] # ./zbx-hpmsa.py --msa MSA-NAME-OR-IP --component disks --get 1.1
    
    OK
  ```
**Zabbix template**  
In addition I've attached preconfigured Zabbix Template here, so you can use it in your environment. It's using Low Level Discovery functionality and {HOST.CONN} macro to determine HTTP connection URL, so make sure that it points to right DNS name or IP. This template expects what your MSA storage has default user with default password - 'monitor'/'!monitor', but if it isn't true - correct it with '-u' and '-p' options (for example "./zbx-hpmsa['-d', '-m', '192.168.1.1', '-c', 'vdisks', '-u', 'FOO', '-p', 'BAR']").

Have fun and rate it on share.zabbix.com if you like it. =)

**Tested with**:  
HP MSA 2040

**Known Issues**:
- ~~Sometimes appears the error "The user is not recognized on this system" though username and password are correct. There is no solve right now, I'm working on it. ~~
 Think I've fixed it in 0.2.5.1.
