import sys
import logging

import pysnmp.hlapi as hlapi
import pysnmp.proto.rfc1902 as rfc1902

import time

TARGET = '10.0.0.8'
community = 'public'
vlan = '30'

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmd_gen = cmdgen.CommandGenerator()
community_data = cmdgen.CommunityData(community)
transport_target = cmdgen.UdpTransportTarget((TARGET, 161), timeout=15, retries=1)

bridge_if_index_oid = '1.3.6.1.2.1.17.1.4.1.2'  # dot1dBasePortIfIndex
index_bridge_oid = '1.3.6.1.2.1.17.4.3.1.2'  # dot1dTpFdbPort

error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
    # cmdgen.CommunityData('%s@%s' % (community, vlan)),
    community_data,
    transport_target,
    0, 30,
    bridge_if_index_oid
)

bridge_if_index_dict = {}
if error_indication:
    logging.error('%s: %s' % (error_indication, TARGET))
    raise Exception(error_indication)
else:
    if error_interface_types:
        logging.error('%s: %s at %s' % (
            TARGET,
            error_interface_types.prettyPrint(),
            error_index and var_bind_table[-1][int(error_index) - 1] or '?'
        ))
    else:
        for varBindTableRow in var_bind_table:
            print(varBindTableRow)
            o0, if_index = varBindTableRow[0]
            mib_tuple = o0._value
            if mib_tuple[:-1] != tuple([int(x) for x in bridge_if_index_oid.split('.')]):
                break
            bridge_number = mib_tuple[-1]
            bridge_if_index_dict[bridge_number] = if_index._value
print(bridge_if_index_dict)
