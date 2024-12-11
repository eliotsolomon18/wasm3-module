import subprocess
import time
import signal
import sys
import iperf3
import os

def main():
    # Build single
    subprocess.run(["make", "clean"], check=True)
    subprocess.run(["make"], check=True)

    # Run single in background
    single_proc = subprocess.Popen(["sudo", "./single"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # Give single some time to set up
    time.sleep(2)

    # Start iperf3 server using the Python wrapper
    server = iperf3.Server()
    server.bind_address = '10.0.1.1'
    server.port = 23557

    # Run server in a separate process to allow non-blocking operation
    # We'll do it by forking a process and running server.run()
    # server.run() is blocking, so we do:
    server_proc = os.fork()
    if server_proc == 0:
        # Child process
        result = server.run()
        # Just exit after server finishes (if ever)
        os._exit(0)
    else:
        # Parent continues
        time.sleep(2)  # Wait for server to start

        # Start iperf3 client using python wrapper
        client = iperf3.Client()
        client.server_hostname = '10.0.1.1'
        client.port = 23557
        client.duration = 10
        client.blksize = 1200

        print("Starting iperf3 client test...")
        client_result = client.run()
        if client_result.error:
            print("Client error:", client_result.error)
        else:
            # Parse results from client_result.json
            sent_bytes = client_result.json['end']['sum_sent']['bytes']
            sent_bps = client_result.json['end']['sum_sent']['bits_per_second']
            sent_mbps = sent_bps / 1e6
            print(f"Client test results:")
            print(f"Transfer: {sent_bytes} bytes, {sent_mbps:.2f} Mbps")

        # Client done, now kill single
        single_proc.send_signal(signal.SIGINT)
        single_proc.wait()
        print("single terminated.")

        # Kill server
        # server_proc is a child process with blocked run(). We can kill it:
        os.kill(server_proc, signal.SIGINT)

        print("All done.")

if __name__ == "__main__":
    main()
