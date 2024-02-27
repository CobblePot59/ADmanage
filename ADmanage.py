import argparse
import json
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from impacket.structure import Structure
import socket
import dns.resolver
import datetime

def parse_arguments():
    parser = argparse.ArgumentParser(description="Process some arguments")
    parser.add_argument('-d', '--domain', required=True, help='Domain name of the target system.')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication.')
    parser.add_argument('-p', '--password', required=True, help='Password for authentication.')
    parser.add_argument('--dc-ip', required=True, help='IP address of the Domain Controller.')
    parser.add_argument('-b', '--base-dn', help='Base Distinguished Name (DN) for LDAP queries.')
    parser.add_argument('-s', '--secure', action='store_true', help='Use SSL for secure communication.')
    parser.add_argument('-M', '--module', required=True, choices=module_functions.keys(), help='Specify the module to execute.')
    parser.add_argument('--data', nargs='+', help='Additional data to pass to the specified module.')
    args = parser.parse_args()

    return args

class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

def new_record(rtype):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = get_next_serial(dc_ip, domain)
    nr['TtlSeconds'] = 180
    # From authoritive zone
    nr['Rank'] = 240
    return nr

def get_next_serial(dc, zone):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    dnsresolver.nameservers = [dc]

    res = dnsresolver.resolve(zone, 'SOA',tcp=False)
    for answer in res:
        return answer.serial + 1


def get_DNSentries():
    filter = "(objectClass=*)"
    conn.search(search_base=dnsroot, search_filter=filter, search_scope=SUBTREE)
    entries = conn.entries
    return [entry.entry_dn for entry in entries if "._tcp" not in entry.entry_dn and "._udp" not in entry.entry_dn]


def get_raw_entry(target):
    filter = f'(&(objectClass=dnsNode)(name={target}))'
    conn.search(search_base=dnsroot, search_filter=filter, attributes=['dnsRecord','dNSTombstoned','name'])
    for entry in conn.response:
        if entry['type'] != 'searchResEntry':
            continue
        return entry


def get_DNSentry(target):
    record_data = get_raw_entry(target)['raw_attributes']['dnsRecord'][0][-4:]
    parsed_record = DNS_RPC_RECORD_A(record_data)
    ip_address = parsed_record.formatCanonical()
    return {'name': get_raw_entry(target)['attributes']['name'], 'ip': ip_address}


def add_DNSentry(target, data):
    record_dn = f'DC={target},{dnsroot}'
    node_data = {
        # Schema is in the root domain (take if from schemaNamingContext to be sure)
        'objectCategory': f'CN=Dns-Node,CN=Schema,CN=Configuration,{domainroot}',
        'dNSTombstoned': False,
        'name': target
    }
    record = new_record(1)
    record['Data'] = DNS_RPC_RECORD_A()
    record['Data'].fromCanonical(data)
    node_data['dnsRecord'] = [record.getData()]
    conn.add(record_dn, ['top', 'dnsNode'], node_data)
    return get_DNSentry(target)


def modify_DNSentry(target, data):
    targetentry = get_raw_entry(target)
    records = []
    for record in targetentry['raw_attributes']['dnsRecord']:
        dr = DNS_RECORD(record)
        if dr['Type'] == 1:
            targetrecord = dr
        else:
            records.append(record)
    targetrecord['Serial'] = get_next_serial(dc_ip, domain)
    targetrecord['Data'] = DNS_RPC_RECORD_A()
    targetrecord['Data'].fromCanonical(data)
    records.append(targetrecord.getData())
    conn.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, records)]})
    return get_DNSentry(target)


def del_DNSentry(target):
    targetentry = get_raw_entry(target)
    diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
    tstime = int(diff.total_seconds()*10000)
    # Add a null record
    record = new_record(0)
    record['Data'] = DNS_RPC_RECORD_TS()
    record['Data']['entombedTime'] = tstime
    conn.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],'dNSTombstoned': [(MODIFY_REPLACE, True)]})


# List all user, group and computer objects
def get_ADobjects():
    search_filter = f"(|(objectClass=user)(objectClass=group)(objectClass=computer))"
    conn.search(base_dn, search_filter, attributes=['*'])

    if conn.entries:
        return conn.entries


# Search for user, group, or computer objects with sAMAccountName value
def get_ADobject(_object):
    search_filter = f"(&(|(objectClass=user)(objectClass=group)(objectClass=computer))(sAMAccountName={_object}))"
    conn.search(base_dn, search_filter, attributes=['*'])

    if conn.entries:
        return conn.entries[0]


# Adding users, computers or groups
def add_ADobject(ou, attributes):
    attributes = json.loads(str(attributes).replace("'", "\""))

    if attributes['objectClass'] == 'user':
        sam = f"{attributes['givenName'].lower()[0]}{attributes['sn'].lower()}"
        cn = f"{attributes['givenName']} {attributes['sn']}"

        password = attributes['password']
        del attributes['password']

        attributes['mail'] = f"{attributes['givenName'].lower()}.{attributes['sn'].lower()}@{domain}"
        attributes['sAMAccountName'] = sam
        attributes['displayName'] = cn
        attributes['cn'] = cn
        attributes['userPrincipalName'] = f"{sam}@{domain}"

        conn.add(f"cn={cn},{ou}", attributes=attributes)
        reset_password(sam, password)
        modify_ADobject_attributes(sam, attributes={'userAccountControl': '512'})

    if attributes['objectClass'] == 'computer':
        sam = f"{attributes['cn'].lower()}$"
        cn = attributes['cn']
        attributes['sAMAccountName'] = sam

        conn.add(f"cn={cn},{ou}", attributes=attributes)


        import string, secrets
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(20))
        reset_password(sam, password)

        changes = {
            'primaryGroupID': '515',
            'userAccountControl': '4096'
        }

        modify_ADobject_attributes(sam, changes)

    if attributes['objectClass'] == 'group':
        sam = f"{attributes['cn'].lower()}"
        cn = attributes['cn']
        attributes['sAMAccountName'] = sam

        conn.add(f"cn={cn},{ou}", attributes=attributes)

    return get_ADobject(sam)


# Removing users, computers or groups
def del_ADobject(_object):
    _object_dn = get_ADobject(_object).distinguishedName
    if conn.delete(_object_dn[0]):
        return 200
    else:
        return None

# List members of group
def get_member(group_name):
    search_filter = f"(&(objectClass=group)(sAMAccountName={group_name}))"
    conn.search(base_dn, search_filter, attributes=['member'])

    if conn.entries:
        return conn.entries[0].member

# List groups of users
def get_memberOf(username):
    search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
    conn.search(base_dn, search_filter, attributes=['memberOf'])

    if conn.entries:
        return conn.entries[0].memberOf


# Adding users, computers, or groups to groups
def add_ADobject_to_group(_object, group):
    _object_dn = get_ADobject(_object).distinguishedName
    group_dn = get_ADobject(group).distinguishedName

    conn.modify(group_dn[0], {'member': [(MODIFY_ADD, [_object_dn[0]])]})
    return get_ADobject(group).member


# Removing users, computers, or groups from groups
def del_ADobject_from_group(_object, group):
    _object_dn = get_ADobject(_object).distinguishedName
    group_dn = get_ADobject(group).distinguishedName

    conn.modify(group_dn[0], {'member': [(MODIFY_DELETE, _object_dn[0])]})
    return get_ADobject(group).member


# Updating user, computer, or group attributes.
def modify_ADobject_attributes(_object, attributes):
    attributes = json.loads(str(attributes).replace("'", "\""))

    _object_dn = get_ADobject(_object).distinguishedName

    for key, value in attributes.items():
        conn.modify(_object_dn[0], {key: [(MODIFY_REPLACE, [value])]})
    return get_ADobject(_object)


# Reset password (Only work with ssl bind)
def reset_password(username, password):
    user_dn = get_ADobject(username).distinguishedName

    if server.ssl:
        if ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, user_dn[0], password, old_password=None):
            return 200
        else:
            return None
    else:
        return 401


# Enable users or computers
def enable_ADobject(_object):
    uacFlag = 2
    old_uac = get_ADobject(_object).userAccountControl
    new_uac = int(str(old_uac)) & ~uacFlag

    attributes = {
        'userAccountControl': new_uac
    }

    modify_ADobject_attributes(_object, attributes)
    return get_ADobject(_object)


# Disable users or computers
def disable_ADobject(_object):
    uacFlag = 2
    old_uac = get_ADobject(_object).userAccountControl
    new_uac = int(str(old_uac)) | uacFlag

    attributes = {
        'userAccountControl': new_uac
    }

    modify_ADobject_attributes(_object, attributes)
    return get_ADobject(_object)


# Test login
def test_login(username, password):
    try:
        server = Server(dc_url, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        if conn:
            return 200
    except:
        return None


if __name__ == '__main__':
    module_functions = {
        'get_DNSentries': get_DNSentries,
        'get_DNSentry': get_DNSentry,
        'add_DNSentry': add_DNSentry,
        'modify_DNSentry': modify_DNSentry,
        'del_DNSentry': del_DNSentry,
        'get_ADobjects': get_ADobjects,
        'get_ADobject': get_ADobject,
        'add_ADobject': add_ADobject,
        'del_ADobject': del_ADobject,
        'get_member': get_member,
        'get_memberOf': get_memberOf,
        'add_ADobject_to_group': add_ADobject_to_group,
        'del_ADobject_from_group': del_ADobject_from_group,
        'modify_ADobject_attributes': modify_ADobject_attributes,
        'reset_password': reset_password,
        'enable_ADobject': enable_ADobject,
        'disable_ADobject': disable_ADobject
    }

    args = parse_arguments()

    domain = args.domain
    username = args.username
    sam = f"{username}@{domain}"
    password = args.password
    dc_ip = args.dc_ip
    base_dn = args.base_dn

    domainroot = f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"
    dnsroot = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}"

    if args.secure:
        dc_url = f"ldaps://{dc_ip}:636"
    else:
        dc_url = f"ldap://{dc_ip}:389"

    if not base_dn:
        base_dn = domainroot

    server = Server(dc_url, get_info=ALL)
    conn = Connection(server, user=sam, password=password, auto_bind=True)

    module = args.module
    selected_function = module_functions.get(module, None)

    if args.data:
        print(selected_function(*args.data))
    else:
        print(selected_function())
