import socket
import threading
import hmac, hashlib
from .proxy import bump

try:
    import tomllib as toml
except ImportError:
    import tomli as toml # type: ignore

with open("ProxySettings.toml", "rb") as f:
    config = toml.load(f)
with open("Users.toml", "rb") as f:
    users = toml.load(f)
HOST = config["remote_addr"]["host"]
PORT = config["remote_addr"]["port"]
LOCALDIR = config["local_addr"]["filepath"]

class AuthError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

class ClientHandler():
    def __init__(self):
        self.authenticated = {}

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(LOCALDIR)
        self.socket.listen()
        while True:
            conn, addr = self.socket.accept()
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn, addr):
        try:
            self.handler = bump.BUMPHandler(conn, is_proxy=True, conn_type=bump.CONNECTION_WITHCLIENT)
            _, block = self.handler.receive(timeout=10)
            if not block or block.type != 0x0000:
                raise AuthError(f"Client {addr} failed to send authentication block")
            if block.read(13) != b"BUMPClient1.1":
                raise AuthError(f"Client {addr} sent invalid or malformed authentication block")
            username = block.read_string()
            if len(username) == 0 or len(username) > 255 or not username in users:
                raise AuthError(f"Client {addr} sent authentication block with invalid username")

            with self.handler.encryption_lock:
                self.handler.send(0x0001, 0, self.handler.secure_value)
                password = users[username]["password"]
                if password.startswith("sha256:"):
                    password = bytes.fromhex(password.removeprefix("sha256:"))
                else:
                    password = password.encode('utf-8')
                self.handler.encryption_key = hmac.new(password, self.handler.secure_value[16:64], hashlib.sha256).digest()[:16]
            
            _, block = self.handler.receive(timeout=10)
            if not block or block.type != 0x0001:
                raise AuthError(f"Client {addr} failed to complete authentication handshake")
            if block.read(8) != b"BUMPTest":
                raise AuthError(f"Client {addr} failed to complete authentication handshake with correct proof")
            
            print("Omg welcome!!!")


        except AuthError as e:
            print(f"Authentication error: {e}")
            conn.close()
            return