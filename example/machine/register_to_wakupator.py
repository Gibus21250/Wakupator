import socket
import json

#Wakupator machine IP & port
ip = '2001:0db8:3c4d:4d58:1::1234'
port = 13717

def send_json(ip, port, data):
    json_data = json.dumps(data)

    #Here change to AF_INET your Wakupator instance is bind on an IPv4
    #AF_INET6 is for IPv6
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        try:

            s.connect((ip, port))
            print(f"Connected to {ip} on port {port}")

            # send JSON
            s.sendall(json_data.encode('utf-8'))
            print("JSON Sended: ", json_data)

            response = s.recv(1024)
            print("Response received: ", response.decode('utf-8'))

        except socket.error as e:
            print(f"Error : {e}")

json_data = {
    "mac": "d8:cb:8a:39:be:a1",
    "monitor": [
        {
            "ip": "2001:0db8:3c4d:4d58:1::2222",
            "port": [25565, 22]
        },
        {
          "ip": "192.168.0.37",
          "port": [22]
        }
    ]
}

send_json(ip, port, json_data)