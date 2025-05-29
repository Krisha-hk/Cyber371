import asyncio
from pysnmp.hlapi.v1arch.asyncio import *

SNMP_SERVER = "192.168.56.4"
SNMP_PORT = 161
COMMUNITY = "public"

async def run():
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        SnmpDispatcher(),
        CommunityData(COMMUNITY),
        await UdpTransportTarget.create((SNMP_SERVER, SNMP_PORT)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
    )

    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds:
            print(f"{varBind[0]} = {varBind[1]}")

asyncio.run(run())
