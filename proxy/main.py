import socketserver
import threading
import time

HOST = "0.0.0.0"
PORT = 5940



class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(1024)
            if not data:
                break
            cur_thread = threading.current_thread()
            response = f"{cur_thread.name}: {data.decode('utf-8')}"
            print(f"Received from client: {data.decode('utf-8').strip()}")
            self.request.sendall(response.encode('utf-8'))
        print(f"Client disconnected: {self.client_address[0]}:{self.client_address[1]}")

def main():
    with socketserver.ThreadingTCPServer((HOST, PORT), ThreadedTCPRequestHandler) as server:
        print(f"Server listening on {HOST}:{PORT}...")
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print(f"Server loop running in thread: {server_thread.name}")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Server shutting down.")
            server.shutdown()

if __name__ == "__main__":
    main()
