import asyncio
from pysnmp.hlapi.v1arch.asyncio import (
    SnmpDispatcher,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd
)

# SNMP server configuration
SNMP_SERVER = "192.168.56.4"  # Replace with your SNMP server IP
SNMP_PORT = 161
COMMUNITY = "public"

async def run():
    # Perform SNMP GET operation
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        SnmpDispatcher(),
        CommunityData(COMMUNITY),
        await UdpTransportTarget.create((SNMP_SERVER, SNMP_PORT)),
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        # Add more ObjectTypes if needed, like sysUpTime, sysName, etc.
    )

    # Handle errors and print the result
    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds:
            print(f"{varBind[0]} = {varBind[1]}")

# Run the async function
asyncio.run(run())
