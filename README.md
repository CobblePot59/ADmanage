[![Maintenance mode](https://img.shields.io/badge/maintenance_mode-%F0%9F%9A%A7-grey.svg?labelColor=orange)](#maintenance-mode)

# ADmanage

The provided script is a Python program that interacts with an Active Directory (AD) server using the LDAP protocol. It allows you to perform various operations on DNS entries and AD objects (users, groups and computers).

:sparkles: Now available on [PyPi](https://pypi.org/project/ADmanage/) :sparkles:

## General Help
![alt text](https://raw.githubusercontent.com/CobblePot59/ADmanage/main/pictures/ADmanage.png)

## Modules Help
#### get_DNSentries
Searches for and returns all DNS entries.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M get_DNSentries
```
#### get_DNSentry
Searches for and returns a specific DNS entry based on its name value.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M get_DNSentry --data 'quad9'
```
#### add_DNSentry
Adds entry to the DNS server.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M add_DNSentry --data 'quad9' '149.112.112.112'
```
#### modify_DNSentry
Modifies attributes of a specified DNS entry.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M modify_DNSentry --data 'quad9' '9.9.9.9'
```
#### del_DNSentry
Deletes a specified DNS entry.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M del_DNSentry --data 'quad9'
```

#### get_ADobjects
Searches for and returns all user, group, and computer objects.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M get_ADobjects
```
#### get_ADobject
Searches for and returns a specific AD object based on its sAMAccountName value.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M get_ADobject --data 'Administrator'
```
#### add_ADobject
Adds users, computers, or groups to the AD server.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M add_ADobject --data 'OU=test,DC=cobblepot59,DC=int' "{'objectClass': 'user', 'givenName': 'Jack', 'sn': 'Bower', 'password': 'Password1'}"
```
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M add_ADobject --data 'OU=test,DC=cobblepot59,DC=int' "{'objectClass': 'computer', 'cn': 'jbower-pc'}"
```
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M add_ADobject --data 'OU=test,DC=cobblepot59,DC=int' "{'objectClass': 'group', 'cn': '24hChrono'}"
```
#### del_ADobject
Deletes a specified AD object.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M del_ADobject --data 'jbower'
```
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M del_ADobject --data 'jbower-pc$'
```
#### get_members
Retrieves the members of a specified group.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M get_members --data 'Administrators'
```
#### get_memberOf
Retrieves the groups to which a user belongs.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M get_memberOf --data 'Administrator'
```
#### add_ADobject_to_group
Adds an AD object to a group.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M add_ADobject_to_group --data 'jbower' 'test'
```
#### del_ADobject_from_group
Removes an AD object from a group.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M del_ADobject_from_group --data 'jbower' 'test'
```
#### modify_ADobject_attributes
Modifies attributes of a specified AD object.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M modify_ADobject_attributes --data 'jbower' "{'mail': 'jack.bower@cobblepot59.int'}"
```
#### reset_password
Resets the password of a user (works with SSL bind).
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M reset_password --data 'jbower' 'Password2'
```
#### enable_ADobject
Enables a user or computer account.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M enable_ADobject --data 'jbower'
```
#### disable_ADobject
Disables a user or computer account.
```sh
ADmanage.py -d 'adcheck.int' -u 'Administrator' -p 'Password1' --dc-ip '192.168.1.1' -M disable_ADobject --data 'jbower-pc$'
```

## Maintenance Mode
There is no active development & new major features are not planned.   
You can use other alternatives like [bloodyAD](https://github.com/CravateRouge/bloodyAD).

