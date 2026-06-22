import asyncio
import json
import os

class Router:
    def __init__(self, name):
        self.name = name
        self.pit = {}  # Interest名 -> 要求元アドレス(複数可)のSet
        self.fib = {}  # プレフィックス -> (転送先ホスト, ポート)
        self._load_fib()

    def _load_fib(self):
        # 環境変数からルーティングテーブルを読み込む (例: "/prefix:host:port,...")
        routes = os.getenv("FIB_ROUTES", "")
        if routes:
            for route in routes.split(","):
                parts = route.split(":")
                if len(parts) == 3:
                    prefix, host, port = parts
                    self.fib[prefix] = (host, int(port))
        print(f"[{self.name}] FIB loaded: {self.fib}")

    def _get_next_hop(self, name):
        # ロンゲストプレフィックスマッチ（最長一致検索）で転送先を決定
        best_match = None
        max_len = -1
        for prefix in self.fib:
            if name.startswith(prefix) and len(prefix) > max_len:
                best_match = prefix
                max_len = len(prefix)
        return self.fib[best_match] if best_match else None

    async def handle_packet(self, data, addr, transport):
        try:
            packet = json.loads(data.decode('utf-8'))
            p_type = packet.get("type")
            name = packet.get("name")

            if p_type == "INTEREST":
                print(f"[{self.name}] Received INTEREST: {name}")
                # PITに登録
                if name not in self.pit:
                    self.pit[name] = set()
                self.pit[name].add(addr)

                # FIBを参照して転送
                next_hop = self._get_next_hop(name)
                if next_hop:
                    transport.sendto(data, next_hop)
                else:
                    print(f"[{self.name}] ⚠️ No route for INTEREST: {name}")

            elif p_type == "DATA":
                print(f"[{self.name}] Received DATA: {name}")
                # PITを参照してInterestの要求元へ送り返す（逆経路転送）
                if name in self.pit:
                    faces = self.pit.pop(name)
                    for face in faces:
                        transport.sendto(data, face)
                else:
                    print(f"[{self.name}] ⚠️ Dropped unsolicited DATA: {name}")
        except Exception as e:
            print(f"[{self.name}] Error handling packet: {e}")

class UDPListener:
    def __init__(self, node): self.node = node
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr):
        asyncio.create_task(self.node.handle_packet(data, addr, self.transport))

async def main():
    name = os.getenv("ROUTER_NAME", "router")
    port = int(os.getenv("PORT", 9000))
    loop = asyncio.get_running_loop()
    router = Router(name)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPListener(router), local_addr=('0.0.0.0', port))
    print(f"Starting {name} on port {port}...")
    await asyncio.sleep(3600)

if __name__ == '__main__':
    asyncio.run(main())