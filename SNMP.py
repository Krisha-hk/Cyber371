import asyncio
from pysnmp.hlapi.v1arch.asyncio import (
    SnmpDispatcher,
    CommunityData,
    UdpTransportTarget,
    ObjectType,
    ObjectIdentity,
    getCmd
)

# SNMP server config
SNMP_SERVER = "192.168.56.4"
SNMP_PORT = 161
COMMUNITY = "public"

async def run():
    # Send SNMP GET request
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        SnmpDispatcher(),
        CommunityData(COMMUNITY),
        await UdpTransportTarget.create((SNMP_SERVER, SNMP_PORT)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))  # .0 is required for scalar OIDs
    )

    # Handle and display the response
    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds:
            print(f"{varBind[0]} = {varBind[1]}")

# Execute the coroutine
asyncio.run(run())
