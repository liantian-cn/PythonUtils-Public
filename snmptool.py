import json
import logging
import struct
import time

from pysnmp.entity.rfc3413.oneliner import cmdgen
# from tornado.log import enable_pretty_logging
import pingscan
# from netaddr import IPNetwork
from netaddr import IPNetwork

# enable_pretty_logging()

logger = logging.getLogger("ICBC")

class SNMPHelper(object):
    def __init__(self, ip, community='public', port=161, timeout=5, retries=1):
        self.ip = ip
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.cmd_gen = cmdgen.CommandGenerator()
        self.community_data = cmdgen.CommunityData(community)
        self.transport_target = cmdgen.UdpTransportTarget((ip, port),
                                                          timeout=timeout,
                                                          retries=retries)

    def get_hostname(self):
        sys_name_oid = '.1.3.6.1.2.1.1.5.0'
        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind = cmd_gen.getCmd(
            self.community_data,
            self.transport_target,
            sys_name_oid,
        )

        hostname = 'Unknown'
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind[int(error_index) - 1] or '?',

                ))
            else:
                oid, hostname = var_bind[0]

        return hostname

    def get_if_index(self):
        if_name_oid = '1.3.6.1.2.1.2.2.1.2'  # ifName
        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            if_name_oid,  # interface name
        )

        interface_dict = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, if_name = varBindTableRow[0]
                    mib_tuple = o0._value
                    if mib_tuple[:-1] != tuple([int(x) for x in if_name_oid.split('.')]):
                        break
                    if_index = mib_tuple[-1]
                    interface_dict[if_index] = if_name.prettyPrint().decode()
        
        return interface_dict

    def get_if_ip(self):
        if_ip_oid_str = '1.3.6.1.2.1.4.20.1.2'  # in RFC1213MIB
        if_mask_oid_str = '1.3.6.1.2.1.4.20.1.3'  # in RFC1213MIB

        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            if_ip_oid_str,
            if_mask_oid_str,
        )

        interface_dict = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0_value, if_index_value = varBindTableRow[0]
                    o1_value, mask_value = varBindTableRow[1]
                    oid_str = o0_value.prettyPrint()
                    oid_str_list = oid_str.split('.')

                    if_index = if_index_value._value
                    mask = mask_value.prettyPrint()
                    if not oid_str.startswith(if_ip_oid_str):
                        break
                    ip_address = '.'.join(oid_str_list[-4:])
                    if_net_list = interface_dict.get(if_index, [])
                    if_net_list.append((ip_address, mask))
                    interface_dict[if_index] = if_net_list
        
        return interface_dict

    def get_if_desc(self):
        if_desc_oid_str = '1.3.6.1.2.1.31.1.1.1.18'

        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            if_desc_oid_str,
        )

        interface_dict = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, if_desc = varBindTableRow[0]
                    mib_tuple = o0._value
                    if mib_tuple[:-1] != tuple([int(x) for x in if_desc_oid_str.split('.')]):
                        break
                    if_index = mib_tuple[-1]
                    interface_dict[if_index] = if_desc.prettyPrint().decode()
        
        return interface_dict


    def get_hsrp(self):
        hsrp_oid_str = '1.3.6.1.4.1.9.9.106.1.2.1.1.11'  # ciscoHsrpMIB
        hsrp_state_oid_str = '1.3.6.1.4.1.9.9.106.1.2.1.1.12'  # ciscoHsrpMIB

        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            hsrp_oid_str,
            hsrp_state_oid_str
        )

        hsrp_list = []
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0_value, ip_value = varBindTableRow[0]
                    _, state_value = varBindTableRow[1]
                    oid_str = o0_value.prettyPrint()
                    if_index = o0_value._value[-2]
                    if not oid_str.startswith(hsrp_oid_str):
                        break
                    if state_value.prettyPrint() != "1":
                        continue
                    hsrp_list.append((if_index, ip_value.prettyPrint()))

        return hsrp_list

    def get_arp(self, if_index_list=None):
        # arp_oid_str = '1.3.6.1.2.1.4.35.1.4'  # ipNetToPhysicalPhysAddress in IPMIB
        # arp_oid_str = '1.3.6.1.2.1.3.1.1.2'  # atPhysAddress in RFC1213MIB
        arp_oid_str = '1.3.6.1.2.1.4.22.1.2'  # ipNetToMediaPhysAddress in RFC1213MIB

        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            arp_oid_str,
        )

        arp_list = []
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    oid_value, mac_value = varBindTableRow[0]
                    oid_str = oid_value.prettyPrint()
                    oid_str_list = oid_str.split('.')
                    if_index = oid_value._value[-5]
                    if not oid_str.startswith(arp_oid_str):
                        break
                    ip_address = '.'.join(oid_str_list[-4:])
                    ss = struct.unpack('!6B', mac_value._value)
                    mac_address = ':'.join(map('{:02x}'.format, ss))
                    arp_list.append((ip_address, mac_address, if_index))

        return arp_list

    def get_cdp_info(self):
        # Return the {if_index: {neighbor: neighbor, remote_port: remote_port}} of cdp info.
        cdp_device_oid = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'
        cdp_remote_if = '1.3.6.1.4.1.9.9.23.1.2.1.1.7'
        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            cdp_device_oid,  # cdp neighbor device id
            cdp_remote_if,  # cdp remote interface name
        )

        cdp_info = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, neighbor = varBindTableRow[0]
                    o1, remote_port = varBindTableRow[1]
                    mib_tuple = o0._value
                    if mib_tuple[:-2] != tuple([int(x) for x in cdp_device_oid.split('.')]):
                        break
                    if_index = mib_tuple[-2]
                    remote_port = remote_port.prettyPrint().decode()
                    neighbor = neighbor.prettyPrint().decode().split('.')[0].split('(')[0]
                    if if_index not in cdp_info:
                        cdp_info[if_index] = []
                    cdp_info[if_index].append(dict(remote_port=remote_port,
                                                   neighbor=neighbor))

        return cdp_info

    def get_vlan_info(self):
        vlan_state_oid = '1.3.6.1.4.1.9.9.46.1.3.1.1.2'  # vtpVlanState
        vlan_type_oid = '1.3.6.1.4.1.9.9.46.1.3.1.1.3'  # vtpVlanType
        vlan_name_oid = '1.3.6.1.4.1.9.9.46.1.3.1.1.4'  # vtpVlanName
        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 30,
            vlan_state_oid,
            vlan_type_oid,
            vlan_name_oid
        )

        vlan_dict = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, vlan_state = varBindTableRow[0]
                    o1, vlan_type = varBindTableRow[1]
                    o2, vlan_name = varBindTableRow[2]
                    mib_tuple = o0._value
                    if mib_tuple[:-2] != tuple([int(x) for x in vlan_state_oid.split('.')]):
                        break
                    if vlan_state._value != 1:
                        continue
                    if vlan_type._value != 1:
                        continue
                    vlan_index = mib_tuple[-1]
                    vlan_dict[vlan_index] = dict(state=vlan_state._value,
                                                 type=vlan_type._value,
                                                 name=vlan_name._value)
        return vlan_dict

    def get_mac_if_info(self, vlan='1'):
        bridge_if_index_oid = '1.3.6.1.2.1.17.1.4.1.2'  # dot1dBasePortIfIndex
        index_bridge_oid = '1.3.6.1.2.1.17.4.3.1.2'  # dot1dTpFdbPort
        cmd_gen = self.cmd_gen

        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            cmdgen.CommunityData('%s@%s' % (self.community, vlan)),
            self.transport_target,
            0, 30,
            bridge_if_index_oid
        )

        bridge_if_index_dict = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, if_index = varBindTableRow[0]
                    mib_tuple = o0._value
                    if mib_tuple[:-1] != tuple([int(x) for x in bridge_if_index_oid.split('.')]):
                        break
                    bridge_number = mib_tuple[-1]
                    bridge_if_index_dict[bridge_number] = if_index._value

        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            cmdgen.CommunityData('%s@%s' % (self.community, vlan)),
            self.transport_target,
            0, 30,
            index_bridge_oid
        )

        mac_list = []
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, bridge_number = varBindTableRow[0]
                    mib_tuple = o0._value
                    if mib_tuple[:-6] != tuple([int(x) for x in index_bridge_oid.split('.')]):
                        break
                    if_index = bridge_if_index_dict.get(bridge_number._value, 0)
                    mac_address = ':'.join(map('{:02x}'.format, mib_tuple[-6:]))
                    mac_list.append((mac_address, if_index))
        return mac_list


def test():


    with open('config.json') as f:
        configs = json.load(f)

    community = configs['snmp']['community']
    retries = configs['snmp']['retries']
    timeout = configs['snmp']['timeout']

    logger.info('Start MAC monitoring')

    for value_zone in configs['host']:
        zone = value_zone.get("zone", "")

        gateway_list = value_zone['gateway']
        access_switch_list = value_zone['access_switch']

        # get ifIndex list for monitored vlans
        device_dict = {}

        s = time.time()
        for host in gateway_list:
            snmp_helper = SNMPHelper(host, community, timeout=timeout, retries=retries)
            hostname = snmp_helper.get_hostname()

            if_index_dict = snmp_helper.get_if_index()  # if_index: if_name
            logger.info("Got if_index for switch %s", hostname)
            print(json.dumps(if_index_dict, indent=2))

            device_dict[host] = dict(snmp_helper=snmp_helper,
                                     if_index_dict=if_index_dict)

            if_ip_list = snmp_helper.get_if_ip()  # if_index: if_name
            logger.info("Got interface ip for switch %s", host)
            print(json.dumps(if_ip_list, indent=2))
            subnets = []
            for ip, mask, if_index, if_desc in if_ip_list:
                if if_index_dict.get(if_index).startswith('Vlan'):
                    ip_net = IPNetwork('%s/%s' % (ip, mask))
                    subnets.append('%s/%s' % (ip_net.network, ip_net.netmask))

            subnets = list(set(subnets))
            ping_socket = pingscan.get_ping_socket()
            for subnet in subnets:
                pingscan.ping_net(subnet, ping_socket)
                time.sleep(0.5)
        
        for host in access_switch_list:
            if host in device_dict:
                snmp_helper = device_dict[host]['snmp_helper']
                if_index_dict = device_dict[host]['if_index_dict']
            else:
                snmp_helper = SNMPHelper(host, community, timeout=timeout, retries=retries)
                hostname = snmp_helper.get_hostname()

                if_index_dict = snmp_helper.get_if_index()  # if_index: if_name
                logger.info("Got if_index for switch %s", hostname)
                print(json.dumps(if_index_dict, indent=2))

                device_dict[host] = dict(snmp_helper=snmp_helper,
                                         if_index_dict=if_index_dict)

            cdp_index_dic = snmp_helper.get_cdp_info()  # if_index: {remote_name, device}
            logger.info("Got CDP info for switch %s", hostname)
            print(json.dumps(cdp_index_dic, indent=2))

            arp_list = snmp_helper.get_arp()
            logger.info("Got ARP table for switch %s", hostname)
            # for ip, mac, if_index in arp_list:
            #     print ip, mac, if_index_dict[if_index]
            print('ARP Count:', len(arp_list))

            vlan_dict = snmp_helper.get_vlan_info()  # vlan: {state, type, name}
            logger.info("Got Vlan info for switch %s", hostname)
            vlans = list(vlan_dict.keys())
            # print json.dumps(vlan_dict, indent=2)

            for vlan_id in vlans:
                mac_ifindex_list = snmp_helper.get_mac_if_info(vlan_id)
                logger.info("Got MAC table for Vlan%s@%s", vlan_id, hostname)
                for mac_address, if_index in mac_ifindex_list:
                    if_name = if_index_dict.get(if_index)
                    if not if_name:
                        continue
                    print(vlan_id, mac_address, if_name)
                print('MAC Count:', len(mac_ifindex_list))

            print(time.time() - s)
        
    logger.info("Done.")


if __name__ == '__main__':
    # test()
    snmp_helper = SNMPHelper("10.0.0.8", "public", timeout=5, retries=1)
    # mac_ifindex_list = snmp_helper.get_mac_if_info(101)
    # print mac_ifindex_list
    # print(snmp_helper.get_if_index())
    print(snmp_helper.get_mac_if_info())
