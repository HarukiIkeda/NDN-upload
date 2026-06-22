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

def encrypt_data(data_str, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data_str.encode('utf-8')) + encryptor.finalize()
    return iv.hex(), cipher_text.hex()

class Producer:
    def __init__(self):
        next_hop = os.getenv("NEXT_HOP_HOST", "router6")
        self.next_hop_addr = (next_hop, 9000)
        self.session_keys = {}

    async def request_chunk(self, session_id, chunk_id, chunk_size, transport):
        # フロー5: I_3 送信
        key = self.session_keys.get(session_id)
        if not key:
            return

        param_dict = {"session_id": session_id, "chunk_id": chunk_id, "chunk_size": chunk_size}
        iv_hex, cipher_hex = encrypt_data(json.dumps(param_dict), key)

        i3_name = f"/network-A/data-request/{session_id}/{chunk_id}"
        i3_packet = {
            "type": "INTEREST",
            "name": i3_name,
            "app_param": {
                "iv": iv_hex,
                "cipher": cipher_hex
            }
        }
        transport.sendto(json.dumps(i3_packet).encode('utf-8'), self.next_hop_addr)
        print(f"[Producer] Sent I_3 requesting chunk {chunk_id}/{chunk_size}")

    async def handle_packet(self, data, addr, transport):
        packet = json.loads(data.decode('utf-8'))
        p_type = packet.get("type")
        name = packet.get("name")
        param = packet.get("app_param", {})

        print(f"[Producer] Received {p_type}: {name}")

        if p_type == "INTEREST" and name.startswith("/producer-01/drive/upload-request"):
            # フロー3: I_2 を受信
            session_id = param.get("session_id")
            chunk_size = param.get("chunk_size")
            p_g_pem = param.get("public_key")

            # ECDH 鍵ペア作成とセッション鍵導出
            priv_key = ec.generate_private_key(ec.SECP256R1())
            pub_bytes = priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.session_keys[session_id] = derive_session_key(priv_key, p_g_pem)
            print(f"[Producer] Session Key Established for {session_id}")

            # D_2 作成・返信
            d2_packet = {
                "type": "DATA",
                "name": name,
                "app_param": {
                    "session_id": session_id,
                    "chunk_size": chunk_size,
                    "public_key": pub_bytes
                }
            }
            transport.sendto(json.dumps(d2_packet).encode('utf-8'), addr)
            print(f"[Producer] Sent D_2 to Gateway")

            # フロー5へ移行 (最初のチャンクを要求)
            asyncio.create_task(self.request_chunk(session_id, 1, chunk_size, transport))

        elif p_type == "DATA" and name.startswith("/network-A/data-request"):
            # フロー8: D_3 を受信
            session_id = param.get("session_id")
            chunk_id = param.get("chunk_id")
            chunk_size = param.get("chunk_size")
            payload = param.get("data")

            print(f"[Producer] Successfully received chunk {chunk_id}: {payload}")

            # 次のチャンクを要求
            if chunk_id < chunk_size:
                asyncio.create_task(self.request_chunk(session_id, chunk_id + 1, chunk_size, transport))
            else:
                print(f"[Producer] 🌟 Upload Complete for session: {session_id} 🌟")

class UDPListener:
    def __init__(self, node): self.node = node
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr):
        asyncio.create_task(self.node.handle_packet(data, addr, self.transport))

async def main():
    loop = asyncio.get_running_loop()
    producer = Producer()
    print("Starting Producer on port 9000...")
    transport, protocol = await loop.create_datagram_endpoint(lambda: UDPListener(producer), local_addr=('0.0.0.0', 9000))
    await asyncio.sleep(3600)

if __name__ == '__main__':
    asyncio.run(main())