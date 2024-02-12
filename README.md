[![Maintenance mode](https://img.shields.io/badge/maintenance_mode-%F0%9F%9A%A7-grey.svg?labelColor=orange)](https://github.com/CobblePot59/ADmanage#maintenance-mode)

# ADmanage

The provided script is a Python program that interacts with an Active Directory (AD) server using the LDAP protocol. It allows you to perform various operations on AD objects such as users, groups, and computers.

:sparkles: Now available on [PyPi](https://pypi.org/project/ADmanage/) :sparkles:

## General Help
![alt text](https://raw.githubusercontent.com/CobblePot59/ADmanage/main/pictures/ADmanage.png)

## Modules Help
#### get_ADobjects
Searches for and returns all user, group, and computer objects.
```sh
Admanage.py -M get_ADobjects
```
#### get_ADobject
Searches for and returns a specific AD object based on its sAMAccountName value.
```sh
Admanage.py -M get_ADobject --data 'Administrator'
```
#### add_ADobject
Adds users, computers, or groups to the AD server.
```sh
Admanage.py -M add_ADobject ---data 'OU=test,DC=cobblepot59,DC=int' "{'objectClass': 'user', 'givenName': 'Jack', 'sn': 'Bower', 'password': 'Password1'}"
```
```sh
Admanage.py -M add_ADobject --data 'OU=test,DC=cobblepot59,DC=int' "{'objectClass': 'computer', 'cn': 'jbower-pc'}"
```
```sh
Admanage.py -M add_ADobject --data 'OU=test,DC=cobblepot59,DC=int' "{'objectClass': 'group', 'cn': '24hChrono'}"
```
#### del_ADobject
Deletes a specified AD object.
```sh
Admanage.py -M del_ADobject --data 'jbower'
```
```sh
Admanage.py -M del_ADobject --data 'jbower-pc$'
```
#### get_member
Retrieves the members of a specified group.
```sh
Admanage.py -M get_member --data 'Administrators'
```
#### get_memberOf
Retrieves the groups to which a user belongs.
```sh
Admanage.py -M get_memberOf --data 'Administrator'
```
#### add_ADobject_to_group
Adds an AD object to a group.
```sh
Admanage.py -M add_ADobject_to_group --data 'jbower' 'test'
```
#### del_ADobject_from_group
Removes an AD object from a group.
```sh
Admanage.py -M del_ADobject_from_group --data 'jbower' 'test'
```
#### modify_ADobject_attributes
Modifies attributes of a specified AD object.
```sh
Admanage.py -M modify_ADobject_attributes --data 'jbower' "{'mail': 'jack.bower@cobblepot59.int'}"
```
#### reset_password
Resets the password of a user (works with SSL bind).
```sh
Admanage.py -M reset_password --data 'jbower' 'Password2'
```
#### enable_ADobject
Enables a user or computer account.
```sh
Admanage.py -M enable_ADobject --data 'jbower'
```
#### disable_ADobject
Disables a user or computer account.
```sh
Admanage.py -M disable_ADobject --data 'jbower-pc$'
```

## Maintenance Mode
There is no active development & new major features are not planned.
You can use other alternatives like [bloodyAD](https://github.com/CravateRouge/bloodyAD).

