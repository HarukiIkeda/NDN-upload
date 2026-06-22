import asyncio
import json
import uuid
import os

class Consumer:
    def __init__(self):
        next_hop = os.getenv("NEXT_HOP_HOST", "gateway")
        self.next_hop_addr = (next_hop, 9000)
        self.my_name = "/network-A/client-01"
        self.session_id = str(uuid.uuid4())[:8]
        self.chunk_size = 3

    async def start_upload(self, transport):
        # フロー1: I_1 送信
        i1_name = f"/producer-01/drive/upload-request/{self.session_id}"
        i1_packet = {
            "type": "INTEREST",
            "name": i1_name,
            "app_param": {
                "consumer_name": self.my_name,
                "session_id": self.session_id,
                "chunk_size": self.chunk_size
            }
        }
        # 修正: self.gateway_addr から self.next_hop_addr に変更
        transport.sendto(json.dumps(i1_packet).encode('utf-8'), self.next_hop_addr)
        print(f"[Consumer] Sent I_1 (Upload Request). Session ID: {self.session_id}")

    async def handle_packet(self, data, addr, transport):
        packet = json.loads(data.decode('utf-8'))
        p_type = packet.get("type")
        name = packet.get("name")
        param = packet.get("app_param", {})

        print(f"[Consumer] Received {p_type}: {name}")

        if p_type == "DATA" and name.startswith("/producer-01/drive/upload-request"):
            # フロー4: D_1 を受信
            print(f"[Consumer] Upload session established via Gateway.")

        elif p_type == "INTEREST" and "/data-request/" in name:
            # フロー7: I_4 を受信
            chunk_id = param.get("chunk_id")
            chunk_size = param.get("chunk_size")
            session_id = param.get("session_id")

            dummy_data = f"Payload-Data-of-Chunk-Index-{chunk_id}"

            # D_4 送信
            d4_packet = {
                "type": "DATA",
                "name": name,
                "app_param": {
                    "session_id": session_id,
                    "chunk_id": chunk_id,
                    "chunk_size": chunk_size,
                    "data": dummy_data
                }
            }
            transport.sendto(json.dumps(d4_packet).encode('utf-8'), addr)
            print(f"[Consumer] Sent D_4 for chunk {chunk_id}")

class UDPListener:
    def __init__(self, node): self.node = node
    def connection_made(self, transport):
        self.transport = transport
        asyncio.create_task(self.trigger_start())
    async def trigger_start(self):
        # 修正: ルータ起動待機を5秒に延長
        await asyncio.sleep(5)
        await self.node.start_upload(self.transport)
    def datagram_received(self, data, addr):
        asyncio.create_task(self.node.handle_packet(data, addr, self.transport))

async def main():
    loop = asyncio.get_running_loop()
    consumer = Consumer()
    print("Starting Consumer on port 9000...")
    # 修正: 9002から9000に統一
    transport, protocol = await loop.create_datagram_endpoint(lambda: UDPListener(consumer), local_addr=('0.0.0.0', 9000))
    await asyncio.sleep(3600)

if __name__ == '__main__':
    asyncio.run(main())