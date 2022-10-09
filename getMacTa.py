import sys

import pysnmp.hlapi as hlapi
import pysnmp.proto.rfc1902 as rfc1902

import time

TARGET = '10.0.0.8'

def snmp_walk(host, oid, format='str', strip_prefix=True, community='public'):
    res = []
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in hlapi.nextCmd(hlapi.SnmpEngine(),
                                    hlapi.CommunityData(community),
                                    hlapi.UdpTransportTarget((host, 161), timeout=4.0, retries=3),
                                    hlapi.ContextData(),
                                    hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
                                    lookupMib=False,
                                    lexicographicMode=False):
        if errorIndication:
            raise ConnectionError(f'SNMP error: "{str(errorIndication)}". Status={str(errorStatus)}')
        elif errorStatus:
            raise ConnectionError('errorStatus: %s at %s' % (errorStatus.prettyPrint(),
                                                             errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for x in varBinds:
                k, v = x
                if strip_prefix:
                    k = str(k)[len(str(oid)) + 1:]
                if isinstance(v, rfc1902.Integer):
                    res.append((str(k), int(v)))
                else:
                    if format == 'numbers':
                        res.append((str(k), v.asNumbers()))
                    elif format == 'hex':
                        res.append((str(k), v.asOctets().hex()))
                    elif format == 'raw':
                        res.append((str(k), v))
                    elif format == 'bin':
                        res.append((str(k), v.asOctets()))
                    elif format == 'int':
                        res.append((str(k), int(v)))
                    elif format == 'preview':
                        res.append((str(k), str(v)))
                    elif format == 'any':
                        try:
                            res.append((str(k), v.asOctets().decode('utf-8')))
                        except UnicodeDecodeError:
                            res.append((str(k), '0x' + v.asOctets().hex()))
                    elif format == 'str':
                        res.append((str(k), v.asOctets().decode(v.encoding)))
                    else:
                        assert False, "Unknown format for walk()."
    res = {a: b for a, b in res}
    return res


def split_numbers(oid):
    return [int(x) for x in oid.split('.')]


def read_ipv4_from_oid_tail(oid, with_len=True):
    parts = [int(x) for x in oid.split('.')]
    if with_len:
        assert (parts[-5] == 4)  # number of elements
    return '.'.join([str(x) for x in parts[-4:]])


def read_bid_from_oid_tail(oid, with_len=True):
    parts = [int(x) for x in oid.split('.')]
    if with_len:
        assert (parts[-5] == 1)  # number of elements
    return '.'.join([str(x) for x in parts[-1:]])


def read_mac_from_oid_tail(oid, with_len=True):
    parts = [int(x) for x in oid.split('.')]
    if with_len:
        assert (parts[-5] == 6)  # number of elements
    return '.'.join([str(x) for x in parts[-6:]])


def machex(getvar):
    macs = getvar.split('.')
    i = 0
    ma = []
    for x in range(0, 6):
        maca = macs[i]
        if len(maca) == 1:
            a = hex(int(maca)).replace("x", "")
        else:
            a = hex(int(maca))[2:]
        ma.append(a)
        i = i + 1
    return ma[0] + ":" + ma[1] + ":" + ma[2] + ":" + ma[3] + ":" + ma[4] + ":" + ma[5]


if __name__ == "__main__":

    # Read ARP table
    print(" - Reading device ARP table...", file=sys.stderr)
    atPhysAddress = snmp_walk(TARGET, '1.3.6.1.2.1.3.1.1.2', 'hex', community='public')
    for oid, mac in atPhysAddress.items():
        ip = read_ipv4_from_oid_tail(oid, with_len=False)
        print(ip)
        print(mac)
    # Read dot1dBasePortIfIndex table

    time.sleep(1)

    print(" - Reading device dot1dBasePortIfIndex table...", file=sys.stderr)
    dot1dBasePortIfIndex = snmp_walk(TARGET, '1.3.6.1.2.1.17.1.4.1.2', 'int', community='public')
    dot1dBasePort = {}
    for bid, id in dot1dBasePortIfIndex.items():
        ip = read_ipv4_from_oid_tail(bid, with_len=False)
        print('bid=', bid)
        print('id=', id)
        dot1dBasePort[bid] = str(id)
    print(dot1dBasePort)

    time.sleep(1)

    # Read ifDescr table
    print(" - Reading device ifDescr table...", file=sys.stderr)
    ifDescr = snmp_walk(TARGET, '1.3.6.1.2.1.2.2.1.2', 'str', community='public')
    Descr = {}
    for id, desc in ifDescr.items():
        ip = read_ipv4_from_oid_tail(id, with_len=False)
        print('id=', id)
        print('desc=', desc)
        Descr[id] = desc
    print(Descr)

    dot1dBasePortDescr = {}
    for key in dot1dBasePort.keys():
        dot1dBasePortDescr[key] = Descr[dot1dBasePort[key]]

    print(dot1dBasePortDescr)

    time.sleep(1)

    # Read dot1qTpFdbPort table
    print(" - Reading device dot1qTpFdbPort table...", file=sys.stderr)
    # dot1qTpFdbPort = snmp_walk(TARGET, '1.3.6.1.2.1.17.4.3.1.2', 'int', community='public')
    # dot1qTpFdbPort = snmp_walk(TARGET, '1.3.6.1.2.1.17.4.3.1.2', 'int', community='public')
    dot1qTpFdbPort = snmp_walk(TARGET, '1.3.6.1.2.1.17.4.3.1.2', 'int', community='public')
    dot1qTpFdb = {}
    for mac, bid in dot1qTpFdbPort.items():
        macdec = read_mac_from_oid_tail(mac, with_len=False)
        print('machex=', machex(macdec))
        print('bid=', bid)
        dot1qTpFdb[machex(macdec)] = str(bid)
    print(dot1qTpFdb)

    dot1qTpFdbDescr = {}
    for key in dot1qTpFdb.keys():
        if dot1qTpFdb[key] in dot1dBasePortDescr.keys():
            dot1qTpFdbDescr[key] = dot1dBasePortDescr[dot1qTpFdb[key]]

    print(dot1qTpFdbDescr)