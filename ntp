import ntplib
from time import ctime

def test_ntp_server(ntp_server='192.168.56.3'):
    """
    Query an NTP server and print the offset and server time.

    Parameters:
    - ntp_server: IP address or hostname of the NTP server.
    """
    client = ntplib.NTPClient()
    try:
        response = client.request(ntp_server, version=3)  # NTP version 3 is common
        print(f"NTP Server: {ntp_server}")
        print(f"Offset: {response.offset:.6f} seconds")
        print(f"Server Time: {ctime(response.tx_time)}")
    except Exception as e:
        print(f"Failed to query NTP server {ntp_server}: {e}")

if __name__ == "__main__":
    test_ntp_server()
