import socket
import threading
import time
from .proxy import bump

try:
    import tomllib as toml
except ImportError:
    import tomli as toml # type: ignore

with open("config.toml", "rb") as f:
    config = toml.load(f)
HOST = config["remote_addr"]["host"]
PORT = config["remote_addr"]["port"]
LOCALDIR = config["local_addr"]["filepath"]

class ClientHandler():
    def __init__(self):
        self.authenticated = {}

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(LOCALDIR)
        self.socket.listen()
    
    def handle_client(self, conn):
        handler = bump.BUMPHandler(conn)