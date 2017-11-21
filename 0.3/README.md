# Version 0.3
## The version is still develops, but you can try it now - common functionality already works.
This version developed special for using with Zabbix 3.4 and it has great new functionality - dependent items.  
Besides of many code correction we have two most important changes:
1. Now zbx-hpmsa depends of 'requests' library. I have to used it because of can't force urllib works with huge XML response (I know, it's my problem, but nothing can do with it);
2. Now we have 'all' argument of '--get' parameter. If you set it like this:
```bash
[asand3r@pc ~]$ ./zbx-hpmsa.py --msa san-001.example.com --component disks --get all
```
you will receive JSON object with all disks status for one request. It's very useful together with Zabbix 3.4 because you needn't make separate requests
to each HP MSA item (disks, vdisks, controllers). Please, read next article to understand use case:
https://www.zabbix.com/documentation/3.4/manual/config/items/itemtypes/dependent_items
