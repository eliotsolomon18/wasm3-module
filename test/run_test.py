from multiprocessing import Process
import subprocess
import socket
import time

test_tcp_block_80= '''
#include <stdint.h>

#include "prog.h"

/*
 * Called by the runtime to handle an incoming IPv4 packet.
 */
uint32_t
filter(void)
{
    return header->prot == TCP && header->dst_pt == 80 ? DROP : ACCEPT;
}
'''

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 23557))
    server_socket.listen(1)
    print("Server started on port 23557")
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Received: {data.decode()}")
        conn.sendall(data)
    conn.close()
    server_socket.close()

def start_client():
    time.sleep(2)  # Wait for the server to start
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 23557))
    for i in range(5):
        message = f"Message {i}"
        client_socket.sendall(message.encode())
        data = client_socket.recv(1024)
        print(f"Received from server: {data.decode()}")
    client_socket.close()

if __name__ == "__main__":
    subprocess.run(["bash", "-c", "./test_setup.sh"], check=True)

    server_process = Process(target=start_server)
    client_process = Process(target=start_client)

    with open("../wasm/prog-test.c", "w") as f:
        f.write(test_tcp_block_80) 

    server_process.start()
    client_process.start()

    client_process.join()
    server_process.terminate()

    subprocess.run(["rm", "../wasm/prog-test.c"], check=True)