import asyncio
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_session_key(private_key, peer_public_key_pem):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_pem.encode('utf-8'))
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ndn-upload').derive(shared_key)

def decrypt_data(iv_hex, cipher_hex, key):
    iv = bytes.fromhex(iv_hex)
    cipher_text = bytes.fromhex(cipher_hex)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(cipher_text) + decryptor.finalize()).decode('utf-8')

class Gateway:
    def __init__(self):
        self.session_table = {}
        self.pit = {}
        self.session_keys = {}
        self.gateway_keys = {}
        
        self.fib = {}
        routes = os.getenv("FIB_ROUTES", "")
        if routes:
            for route in routes.split(","):
                parts = route.split(":")
                if len(parts) == 3:
                    self.fib[parts[0]] = (parts[1], int(parts[2]))
        print(f"[Gateway] FIB loaded: {self.fib}")

    def _get_next_hop(self, name):
        best_match = None
        max_len = -1
        for prefix in self.fib:
            if name.startswith(prefix) and len(prefix) > max_len:
                best_match = prefix
                max_len = len(prefix)
        return self.fib[best_match] if best_match else None

    async def handle_packet(self, data, addr, transport):
        packet = json.loads(data.decode('utf-8'))
        p_type = packet.get("type")
        name = packet.get("name")
        param = packet.get("app_param", {})

        print(f"[Gateway] Received {p_type}: {name}")

        if p_type == "INTEREST":
            # フロー2: I_1 を受信
            if name.startswith("/producer-01/drive/upload-request"):
                session_id = param.get("session_id")
                consumer_name = param.get("consumer_name")
                chunk_size = param.get("chunk_size")

                self.session_table[session_id] = consumer_name
                self.pit[name] = addr

                priv_key = ec.generate_private_key(ec.SECP256R1())
                pub_bytes = priv_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                self.gateway_keys[session_id] = (priv_key, pub_bytes)

                i2_packet = {
                    "type": "INTEREST",
                    "name": name,
                    "app_param": {
                        "gateway_name": "/network-A",
                        "session_id": session_id,
                        "chunk_size": chunk_size,
                        "public_key": pub_bytes
                    }
                }
                
                # 修正: _get_next_hop を使用
                next_hop = self._get_next_hop("/producer-01/drive")
                if next_hop:
                    transport.sendto(json.dumps(i2_packet).encode('utf-8'), next_hop)
                    print(f"[Gateway] Sent I_2 to Producer")

            # フロー6: I_3 を受信
            elif name.startswith("/network-A/data-request"):
                parts = name.split('/')
                session_id = parts[3]
                
                self.pit[name] = addr

                key = self.session_keys.get(session_id)
                decrypted_str = decrypt_data(param["iv"], param["cipher"], key)
                decrypted_param = json.loads(decrypted_str)
                print(f"[Gateway] Decrypted I_3 params: {decrypted_param}")

                consumer_name = self.session_table.get(session_id)
                if consumer_name:
                    i4_name = f"{consumer_name}/data-request/{session_id}/{decrypted_param['chunk_id']}"
                    i4_packet = {
                        "type": "INTEREST",
                        "name": i4_name,
                        "app_param": decrypted_param
                    }
                    # 修正: _get_next_hop を使用
                    next_hop = self._get_next_hop(consumer_name)
                    if next_hop:
                        transport.sendto(json.dumps(i4_packet).encode('utf-8'), next_hop)
                        print(f"[Gateway] Sent I_4 to Consumer")

        elif p_type == "DATA":
            # フロー4: D_2 を受信
            if name.startswith("/producer-01/drive/upload-request"):
                session_id = param.get("session_id")
                p_p_pem = param.get("public_key")

                priv_key = self.gateway_keys[session_id][0]
                self.session_keys[session_id] = derive_session_key(priv_key, p_p_pem)
                print(f"[Gateway] Session Key Established for {session_id}")

                consumer_addr = self.pit.pop(name, None)
                if consumer_addr:
                    d1_packet = {
                        "type": "DATA",
                        "name": name,
                        "app_param": {"status": "ACK", "session_id": session_id}
                    }
                    transport.sendto(json.dumps(d1_packet).encode('utf-8'), consumer_addr)
                    print(f"[Gateway] Sent D_1 (ACK) to Consumer")

            # フロー7: D_4 を受信してD_3として中継
            elif "/data-request/" in name:
                parts = name.split('/')
                session_id = parts[4]
                chunk_id = parts[5]

                i3_name = f"/network-A/data-request/{session_id}/{chunk_id}"
                producer_addr = self.pit.pop(i3_name, None)
                if producer_addr:
                    d3_packet = {
                        "type": "DATA",
                        "name": i3_name,
                        "app_param": param
                    }
                    transport.sendto(json.dumps(d3_packet).encode('utf-8'), producer_addr)
                    print(f"[Gateway] Relayed D_4 as D_3 to Producer")

class UDPListener:
    def __init__(self, node): self.node = node
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr):
        asyncio.create_task(self.node.handle_packet(data, addr, self.transport))

async def main():
    loop = asyncio.get_running_loop()
    gateway = Gateway()
    print("Starting Gateway on port 9000...")
    # 修正: 9001から9000に統一
    transport, protocol = await loop.create_datagram_endpoint(lambda: UDPListener(gateway), local_addr=('0.0.0.0', 9000))
    await asyncio.sleep(3600)

if __name__ == '__main__':
    asyncio.run(main())