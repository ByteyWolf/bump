import math
import struct
import secrets
import threading
import time
import queue
from . import cryptutil
from . import waitabledict

STATE_HANDSHAKE = 0
STATE_AUTHORIZING = 1
STATE_READY = 2

CONNECTION_WITHCLIENT = 0
CONNECTION_WITHSERVER = 1

class BUMPSettings():
    handshake_timeout = 30
    max_packet_size = 10 * 1024 * 1024
    max_packet_size_handshake = 10 * 1024
    max_traffic_per_minute = 1024 * 1024
    message_timeout = 60

class BUMPBlock():
    def __init__(self, blockid, flags, blocktype, data, incoming=False, encrypted=False):
        self.id = blockid
        self.flags = flags
        self.type = blocktype
        self.data = data
        self.encrypted = encrypted
        self.incoming = incoming
        self.timestamp = time.time()

class BUMPHandler():
    def __init__(self, connection, is_proxy=False, conn_type=CONNECTION_WITHCLIENT, settings=BUMPSettings()):
        if not connection:
            raise ValueError("Connection cannot be None")
        
        self.settings = settings
        self.outgoing_queue:queue.Queue[BUMPBlock] = queue.Queue()
        self.incoming_queue:waitabledict.WaitableDict = waitabledict.WaitableDict()
        self.outgoing_lock = threading.Lock()

        self.secure_value = secrets.token_bytes(64)
        self.incoming_counter = 0
        self.outgoing_counter = 0
        self.state = STATE_HANDSHAKE
        self.encryption_key = None
        self.connection = connection
        self.connection_type = conn_type

        self.total_incoming_traffic_bytes = 0

        self.timer = 0
        self.closed = False

        # the proxy never connects to anyone first
        if is_proxy:
            self.incoming_counter = 0xFFFFFFFF
        else:
            self.outgoing_counter = 0xFFFFFFFF

    def recv_length(self):
        packetlenlen = 0
        packetlen = b''
        while packetlenlen < 4:
            chunk = self.connection.recv(4 - packetlenlen)
            if not chunk:
                raise ConnectionError("Connection closed by peer")
            packetlen += chunk
            packetlenlen += len(chunk)

            # goddamn nested if
            if self.state == STATE_HANDSHAKE or self.state == STATE_AUTHORIZING:
                if time.time() - self.timer > self.settings.handshake_timeout:
                    raise TimeoutError("Handshake timed out")
                if packetlen > self.settings.max_packet_size_handshake:
                    raise ValueError(f"Packet length {packetlen} exceeds maximum allowed {self.settings.max_packet_size_handshake}")
                    
        return struct.unpack('>I', packetlen)[0]
    
    def recv_data(self, length):
        data = b''
        while len(data) < length:
            chunk = self.connection.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by peer")
            data += chunk
        return data
    
    def check_ratelimit(self):
        if math.ceil((time.time() - self.timer) / 60) * self.settings.max_traffic_per_minute < self.total_incoming_traffic_bytes:
            raise Exception("Client exceeded maximum traffic limit")

    def handle_incoming_forever(self):
        self.connection.settimeout(self.settings.handshake_timeout)
        self.timer = time.time()
        while True:
            if self.closed:
                break

            try:
                packetlen = self.recv_length()
                data = self.recv_data(packetlen)
                self.total_incoming_traffic_bytes += packetlen + 4
                self.check_ratelimit()
                
                if self.encryption_key:
                    data = self.decrypt(data)

                self.incoming_counter = (self.incoming_counter + 1) & 0xFFFFFFFF
                blockid, flags, blocktype = struct.unpack('>QBH', data[:11])
                blockid = blockid & 0xFFFFFFFF
                blockdata = data[11:]
                self.incoming_queue[blockid] = BUMPBlock(blockid, flags, blocktype, blockdata, incoming=True)
            except ConnectionError:
                break
            except Exception as e:
                print(f"Error receiving packet: {e}")
                break
        self.closed = True
    
    def handle_outgoing_forever(self):
        while True:
            if self.closed:
                break

            block = self.outgoing_queue.get(timeout=5.0)
            if not block:
                continue
            
            with self.outgoing_lock:
                payload = struct.pack('>QBH', block.id, block.flags, block.type) + block.data
                if block.encrypted:
                    payload = self.encrypt(payload)
                payload_length = len(payload)
                payload = struct.pack('>I', payload_length) + payload
                self.connection.sendall(payload)
        self.closed = True

    def cleanup_incoming(self):
        keys = []
        for key in self.incoming_queue:
            val = self.incoming_queue[key]
            timestamp = val.timestamp
            if time.time() - timestamp > self.settings.message_timeout:
                keys.append(key)
        for key in keys:
            del self.incoming_queue[key]

    def encrypt(self, payload:bytes) -> bytes:
        # TODO
        assert self.encryption_key, "Encryption is not ready yet!"
        return b''
    
    def decrypt(self, payload:bytes) -> bytes:
        # TODO
        assert self.encryption_key, "Encryption is not ready yet!"
        return b''
    
    """Make a BUMP request and wait for a response. Returns the response block or None if no response was received within the timeout."""
    def request(self, blocktype:int, data:bytes, timeout=30) -> BUMPBlock|None:
        blockid = self.outgoing_counter
        self.outgoing_counter = (self.outgoing_counter + 1) & 0xFFFFFFFF
        block = BUMPBlock(blockid, 0, blocktype, data, encrypted=self.state == STATE_READY)
        self.outgoing_queue.put(block)
        result = self.incoming_queue.wait(blockid, timeout=timeout)
        if result:
            del self.incoming_queue[blockid]
        return result
    
    """Send a BUMP block without waiting for a response."""
    def send(self, blocktype:int, flags:int, data:bytes):
        blockid = self.outgoing_counter
        self.outgoing_counter = (self.outgoing_counter + 1) & 0xFFFFFFFF
        block = BUMPBlock(blockid, flags, blocktype, data, encrypted=self.state == STATE_READY)
        self.outgoing_queue.put(block)