from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd
)

SNMP_SERVER = "192.168.56.4"
COMMUNITY = "public"

def query_snmp():
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(
            SnmpEngine(),
            CommunityData(COMMUNITY, mpModel=1),  # SNMPv2c
            UdpTransportTarget((SNMP_SERVER, 161), timeout=1, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        )
    )

    if errorIndication:
        print(f"Error: {errorIndication}")
    elif errorStatus:
        print(f"Error: {errorStatus.prettyPrint()}")
    else:
        for varBind in varBinds:
            print(f"{varBind[0]} = {varBind[1]}")

if __name__ == "__main__":
    query_snmp()
