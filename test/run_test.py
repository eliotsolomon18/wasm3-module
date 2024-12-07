import subprocess
import socket
import time
from multiprocessing import Process, Queue
from enum import Enum

test_tcp_block_23557 = """
#include <stdint.h>

#include "prog.h"

/*
 * Drop TCP packets destined for port 23557
 */
uint32_t
filter(void)
{
    return header->prot == TCP && header->dst_pt == 23557 ? DROP : ACCEPT;
}
"""

test_dummy = """
#include <stdint.h>

#include "prog.h"

/*
 * Simply returns ACCEPT.
 */
uint32_t
filter(void)
{
    return ACCEPT;
}
"""

test_tcp_passthrough_23557 = """
#include <stdint.h>

#include "prog.h"

/*
 * Let 23557 traffic pass through
 */
uint32_t
filter(void)
{
    return header->dst_pt == 23557 || header->src_pt == 23557 ? ACCEPT : DROP;
}
"""

class Result(Enum):
    SUCCESS = 0
    TIMEOUT = 1

def start_server(queue):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 23557))
    server_socket.listen(1)
    print("Server started on port 23557")
    server_socket.settimeout(5)
    try:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode()}")
            conn.sendall(data)
        conn.close()
        queue.put(Result.SUCCESS)
    except socket.timeout:
        print("Server connection timed out")
        queue.put(Result.TIMEOUT)
    finally:
        server_socket.close()

def start_client(queue):
    time.sleep(2)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5)
    try:
        client_socket.connect(('127.0.0.1', 23557))
        for i in range(5):
            message = f"Message {i}"
            client_socket.sendall(message.encode())
            data = client_socket.recv(1024)
            print(f"Received from server: {data.decode()}")
        queue.put(Result.SUCCESS)
    except socket.timeout:
        queue.put(Result.TIMEOUT)
        print("Client connection timed out")
    finally:
        client_socket.close()

def run_test(test_program):
    with open("wasm/prog-test.c", "w") as f:
        f.write(test_program)

    subprocess.run(["bash", "-c", "test/test_setup.sh"], check=True)

    queue = Queue()
    server_process = Process(target=start_server, args=(queue,))
    client_process = Process(target=start_client, args=(queue,))

    server_process.start()
    client_process.start()

    client_process.join()
    print("Client process finished")
    server_process.join()
    print("Server process finished")

    print("Fetching results")
    client_result = queue.get(timeout=5)
    server_result = queue.get(timeout=5)

    subprocess.run(["bash", "-c", "test/test_cleanup.sh"], check=True)

    return client_result, server_result

if __name__ == "__main__":
    test_programs = [
        ("test_dummy", test_dummy, Result.SUCCESS, Result.SUCCESS),
        ("test_tcp_block_23557", test_tcp_block_23557, Result.TIMEOUT, Result.TIMEOUT),
        ("test_tcp_passthrough_23557", test_tcp_passthrough_23557, Result.SUCCESS, Result.SUCCESS),
        # What other tests should we run?
    ]

    results = []

    for test_name, test_program, client_expected_result, server_expected_result in test_programs:
        client_result, server_result = run_test(test_program)
        if client_result == client_expected_result and server_result == server_expected_result:
            result = f"Test {test_name} PASSED - Client Result: {client_result}, Server Result: {server_result}"
        else:
            result = f"Test {test_name} FAILED - Client Result: {client_result}, Server Result: {server_result}, Expected Result (Client): {client_expected_result}, Expected Result (Server): {server_expected_result}"
        results.append(result)
        print(result)

    print("\nSummary of test results:")
    for result in results:
        print(result)