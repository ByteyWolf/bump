import math
import struct
import secrets
import threading
import time
import queue
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
        self.pointer = 0
    
    """Read a specific amount of bytes from the block data, advancing the pointer. Returns b'' if the pointer is at or past the end of the data."""
    def read(self, amount=4) -> bytes:
        if self.pointer >= len(self.data):
            return b''
        result = self.data[self.pointer:self.pointer+amount]
        self.pointer += amount
        return result
    
    """Read UTF-8 encoded null-terminated string from the block data, advancing the pointer. Returns an empty string if the pointer is at or past the end of the data."""
    def read_string(self) -> str:
        if self.pointer >= len(self.data):
            return ''
        end = self.data.find(b'\x00', self.pointer)
        if end == -1:
            end = len(self.data)
        result = self.data[self.pointer:end].decode('utf-8')
        self.pointer = end + 1
        return result
    
    """Read a big-endian unsigned integer from the block data, advancing the pointer. Returns None if there are not enough bytes left to read an integer."""
    def read_int(self, size=4) -> int | None:
        if self.pointer + size > len(self.data):
            return None
        result = int.from_bytes(self.data[self.pointer:self.pointer+size], 'big')
        self.pointer += size
        return result

class BUMPHandler():
    def __init__(self, connection, is_proxy=False, conn_type=CONNECTION_WITHCLIENT, settings=BUMPSettings()):
        if not connection:
            raise ValueError("Connection cannot be None")
        
        self.settings = settings
        self.outgoing_queue:queue.Queue[BUMPBlock] = queue.Queue()
        self.incoming_queue:waitabledict.WaitableDict[int, BUMPBlock] = waitabledict.WaitableDict()
        self.outgoing_lock = threading.Lock()
        self.encryption_lock = threading.Lock()

        self.secure_value = secrets.token_bytes(64)
        self.incoming_counter = 0
        self.outgoing_counter = 0
        self.state = STATE_HANDSHAKE
        self.encryption_key:None|bytes = None
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

    def _recv_length(self):
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
                if struct.unpack('>I', packetlen)[0] > self.settings.max_packet_size_handshake:
                    raise ValueError(f"Packet length {packetlen} exceeds maximum allowed {self.settings.max_packet_size_handshake}")
                    
        return struct.unpack('>I', packetlen)[0]
    
    def _recv_data(self, length):
        data = b''
        while len(data) < length:
            chunk = self.connection.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by peer")
            data += chunk
        return data
    
    def _check_ratelimit(self):
        if math.ceil((time.time() - self.timer) / 60) * self.settings.max_traffic_per_minute < self.total_incoming_traffic_bytes:
            raise Exception("Client exceeded maximum traffic limit")

    def _handle_incoming_forever(self):
        self.connection.settimeout(self.settings.handshake_timeout)
        self.timer = time.time()
        while True:
            if self.closed:
                break

            try:
                packetlen = self._recv_length()
                data = self._recv_data(packetlen)
                self.total_incoming_traffic_bytes += packetlen + 4
                self._check_ratelimit()

                with self.encryption_lock:
                    if self.encryption_key:
                        data = self._decrypt(data)

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
    
    def _handle_outgoing_forever(self):
        while True:
            if self.closed:
                break

            try:
                block = self.outgoing_queue.get(block=True, timeout=5.0)
            except queue.Empty:
                continue
            
            with self.outgoing_lock:
                payload = struct.pack('>QBH', block.id, block.flags, block.type) + block.data
                if block.encrypted:
                    payload = self._encrypt(payload)
                payload_length = len(payload)
                payload = struct.pack('>I', payload_length) + payload
                self.connection.sendall(payload)
        self.closed = True

    def _cleanup_incoming(self):
        keys = []
        for key in self.incoming_queue:
            val = self.incoming_queue[key]
            timestamp = val.timestamp
            if time.time() - timestamp > self.settings.message_timeout:
                keys.append(key)
        for key in keys:
            del self.incoming_queue[key]

    def _derive_iv(self, counter: int) -> bytes:
        base = self.secure_value[:12]
        return bytes(a ^ b for a, b in zip(base, b"\x00\x00\x00\x00" + struct.pack(">Q", counter)))

    def _encrypt(self, payload:bytes) -> bytes:
        # TODO
        assert self.encryption_key, "Encryption is not ready yet!"
        return AESGCM(self.encryption_key).encrypt(self._derive_iv(self.outgoing_counter), payload, None)
    
    def _decrypt(self, payload:bytes) -> bytes:
        # TODO
        assert self.encryption_key, "Encryption is not ready yet!"
        return AESGCM(self.encryption_key).decrypt(self._derive_iv(self.incoming_counter), payload, None)
    

    def request(self, blocktype:int, data:bytes, timeout=30) -> BUMPBlock|None:
        """Make a BUMP request and wait for a response. Returns the response block or None if no response was received within the timeout."""
        blockid = self.outgoing_counter
        self.outgoing_counter = (self.outgoing_counter + 1) & 0xFFFFFFFF
        block = BUMPBlock(blockid, 0, blocktype, data, encrypted=self.state == STATE_READY)
        self.outgoing_queue.put(block)
        result = self.incoming_queue.wait(blockid, timeout=timeout)
        if result:
            del self.incoming_queue[blockid]
        return result
    
    def send(self, blocktype:int, flags:int, data:bytes):
        """Send a BUMP block without waiting for a response."""
        blockid = self.outgoing_counter
        self.outgoing_counter = (self.outgoing_counter + 1) & 0xFFFFFFFF
        block = BUMPBlock(blockid, flags, blocktype, data, encrypted=self.state == STATE_READY)
        self.outgoing_queue.put(block)
    
    def receive(self, timeout=30) -> tuple[int|None, BUMPBlock|None]:
        """Get the latest BUMP block of any type as soon as it arrives, or None if no block was received within the timeout."""
        return self.incoming_queue.wait_any(timeout=timeout) or (None, None)