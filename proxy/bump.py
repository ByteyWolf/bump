import queue
import struct
import secrets
import threading
from . import cryptutil

STATE_HANDSHAKE = 0
STATE_AUTHORIZING = 1
STATE_READY = 2

CONNECTION_WITHCLIENT = 0
CONNECTION_WITHSERVER = 1

class BUMPBlock():
    def __init__(self, id, flags, type, data, encrypted=False):
        self.id = id
        self.flags = flags
        self.type = type
        self.data = data
        self.encrypted = encrypted
    
    def bake(self, handler: BUMPHandler):
        payload = struct.pack('>QBH', self.id, self.flags, self.type) + self.data
        if self.encrypted:
            # Placeholder for encryption logic
            payload = self.encrypt(payload)
        payload_length = len(payload)
        payload = struct.pack('>I', payload_length) + payload
        return payload

class BUMPHandler():
    def __init__(self, connection, is_proxy=False, conn_type=CONNECTION_WITHCLIENT):
        if not connection:
            raise ValueError("Connection cannot be None")
        self.outgoing_queue = queue.Queue()
        self.incoming_queue = queue.Queue()
        self.outgoing_lock = threading.Lock()
        self.incoming_lock = threading.Lock()

        self.secure_value = secrets.token_bytes(64)
        self.incoming_counter = 0
        self.outgoing_counter = 0
        self.state = STATE_HANDSHAKE
        self.encryption_key = None
        self.connection = connection
        self.connection_type = conn_type
        # the proxy never connects to anyone first
        if is_proxy:
            self.incoming_counter = 0xFFFFFFFF
        else:
            self.outgoing_counter = 0xFFFFFFFF

    def handle_forever(self):
        pass
