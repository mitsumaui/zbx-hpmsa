# zbx-hpmsa
Zabbix module to monitor HP MSA storages

Zabbix Share page: https://share.zabbix.com/component/mtree/storage-devices/hp/hp-msa-2040-xml-api

Also you can contact with me in vk.com: https://vk.com/asand3r

zbx-hpmsa provides possibility to make LLD of physical and virtual disks on HP MSA storages via it's XML API. Also it can gets status of discovered component.
Program wrote with Python 3.5, but works with Python 3.4 (I didn't check it with earlier versions, sorry) and doesn't depends of any external library.

Latest version is 0.2.4.

Feautres

Low Level Discovery:
  * physical disks 
  * virtual disks

Component status:
  * physical disks 
  * virtual disks

Usage
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
Zabbix template
Also I've attached here preconfigured Zabbix Template, so you can use it in your environment. It's using Low Level Discovery functionality and {HOST.CONN} macro to determine http connection URL, so make sure that it points to right DNS name or IP.

Have fun and rate it on share.zabbix.com if you like it. =)
