import asyncio
import socket
import json
import logging
import netifaces
from networking.utils import get_own_ip
from networking.shared_state import user_data, shutdown_event

class PeerDiscovery:
    def __init__(self, broadcast_interval=5, cleanup_interval=60):
        self.broadcast_port = 37020
        self.peer_list = {}
        self.broadcast_interval = broadcast_interval
        self.cleanup_interval = cleanup_interval
        self.running = True
        self._send_socket = None
        self._receive_socket = None
        self._own_ip_cache = None


    async def _get_own_ip_cached(self):
        if self._own_ip_cache is None:
            self._own_ip_cache = await get_own_ip()
        return self._own_ip_cache

    def _create_send_socket(self):
         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
         sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
         sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         return sock

    def _create_receive_socket(self):
         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
         sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         try:
             sock.bind(("", self.broadcast_port))
             sock.setblocking(False)
             logging.info(f"Discovery listening on port {self.broadcast_port}")
             return sock
         except OSError as e:
             logging.critical(f"Could not bind discovery receive socket to port {self.broadcast_port}: {e}. Discovery disabled.")
             self.running = False
             return None


    async def send_broadcasts(self):
        self._send_socket = self._create_send_socket()
        try:
            while self.running and not shutdown_event.is_set():
                try:
                    own_ip = await self._get_own_ip_cached()
                    username = user_data.get("original_username", "unknown")
                    if not username or username == "unknown":
                         logging.warning("Username not set, cannot send discovery broadcast.")
                         await asyncio.sleep(self.broadcast_interval)
                         continue

                    message = json.dumps({"ip": own_ip, "username": username}).encode()
                    broadcast_addresses = []
                    for interface in netifaces.interfaces():
                        try:
                            if netifaces.AF_INET in netifaces.ifaddresses(interface):
                                addrs = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                                if addrs:
                                    broadcast_addr = addrs[0].get("broadcast")
                                    if broadcast_addr:
                                        broadcast_addresses.append(broadcast_addr)
                        except (OSError, KeyError, Exception) as e:
                             logging.debug(f"Error getting broadcast for {interface}: {e}")

                    unique_broadcast_addresses = set(broadcast_addresses)
                    if not unique_broadcast_addresses:
                         logging.warning("No broadcast addresses found to send discovery message.")

                    for broadcast_addr in unique_broadcast_addresses:
                         try:
                             self._send_socket.sendto(message, (broadcast_addr, self.broadcast_port))
                             logging.debug(f"Sent broadcast to {broadcast_addr}:{self.broadcast_port}")
                         except OSError as e:
                             logging.error(f"Network error sending broadcast to {broadcast_addr}: {e}")
                         except Exception as e:
                              logging.error(f"Unexpected error sending broadcast to {broadcast_addr}: {e}")

                except Exception as outer_e:
                    logging.error(f"Error preparing/sending broadcast message: {outer_e}")

                await asyncio.sleep(self.broadcast_interval)
        finally:
            if self._send_socket:
                 self._send_socket.close()
                 self._send_socket = None
            logging.info("send_broadcasts task stopped.")

    async def receive_broadcasts(self):
        self._receive_socket = self._create_receive_socket()
        if not self._receive_socket:
            return

        loop = asyncio.get_event_loop()
        own_ip = await self._get_own_ip_cached()
        try:
            while self.running and not shutdown_event.is_set():
                try:
                    ready = await loop.sock_recv(self._receive_socket, 1) # Check if ready
                    if ready:
                        data, (sender_ip, _) = await loop.sock_recvfrom(self._receive_socket, 1024)
                        current_time = loop.time()

                        if sender_ip == own_ip:
                            continue

                        message_str = data.decode('utf-8', errors='ignore')
                        message = json.loads(message_str)
                        peer_ip = message["ip"]
                        username = message["username"]

                        # Add/update peer in the list with timestamp
                        self.peer_list[peer_ip] = (username, current_time)
                        logging.debug(f"Received broadcast from {username} ({peer_ip})")

                except json.JSONDecodeError:
                    logging.warning(f"Invalid JSON broadcast received from {sender_ip}")
                except KeyError:
                    logging.warning(f"Malformed broadcast received from {sender_ip} (missing fields)")
                except UnicodeDecodeError:
                    logging.warning(f"Non-UTF8 broadcast received from {sender_ip}")
                except BlockingIOError:
                    # No data available, sleep briefly
                    await asyncio.sleep(0.1)
                except OSError as e:
                    # Handle specific errors like network unreachable if necessary
                    logging.error(f"Network error receiving broadcast: {e}")
                    await asyncio.sleep(1) # Wait a bit longer after network errors
                except Exception as e:
                    # Catch unexpected errors
                    logging.exception(f"Unexpected error receiving broadcast: {e}")
                    await asyncio.sleep(0.5)

        finally:
            if self._receive_socket:
                 self._receive_socket.close()
                 self._receive_socket = None
            logging.info("receive_broadcasts task stopped.")

    async def cleanup_stale_peers(self):
        while self.running and not shutdown_event.is_set():
            try:
                current_time = asyncio.get_event_loop().time()
                stale_timeout = self.cleanup_interval * 1.5 # Remove if not seen for 1.5x interval
                stale_peers = [
                    peer_ip for peer_ip, (_, last_seen) in self.peer_list.items()
                    if current_time - last_seen > stale_timeout
                ]
                for peer_ip in stale_peers:
                    if peer_ip in self.peer_list:
                        removed_username = self.peer_list[peer_ip][0]
                        del self.peer_list[peer_ip]
                        logging.info(f"Removed stale discovered peer: {removed_username} ({peer_ip})")

            except Exception as e:
                logging.exception(f"Error during stale peer cleanup: {e}")

            await asyncio.sleep(self.cleanup_interval)
        logging.info("cleanup_stale_peers task stopped.")


    async def send_immediate_broadcast(self):
        temp_sock = self._create_send_socket()
        try:
            own_ip = await self._get_own_ip_cached()
            username = user_data.get("original_username", "unknown")
            if not username or username == "unknown":
                 logging.warning("Username not set, cannot send immediate broadcast.")
                 return

            message = json.dumps({"ip": own_ip, "username": username}).encode()
            broadcast_addresses = []
            for interface in netifaces.interfaces():
                try:
                    if netifaces.AF_INET in netifaces.ifaddresses(interface):
                        addrs = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                        if addrs:
                            broadcast_addr = addrs[0].get("broadcast")
                            if broadcast_addr:
                                broadcast_addresses.append(broadcast_addr)
                except (OSError, KeyError, Exception) as e:
                     logging.debug(f"Error getting broadcast for {interface}: {e}")

            unique_broadcast_addresses = set(broadcast_addresses)
            if not unique_broadcast_addresses:
                 logging.warning("No broadcast addresses found for immediate broadcast.")

            for broadcast_addr in unique_broadcast_addresses:
                 try:
                     temp_sock.sendto(message, (broadcast_addr, self.broadcast_port))
                     logging.debug(f"Sent immediate broadcast to {broadcast_addr}:{self.broadcast_port}")
                 except OSError as e:
                     logging.error(f"Network error sending immediate broadcast to {broadcast_addr}: {e}")
                 except Exception as e:
                      logging.error(f"Unexpected error sending immediate broadcast to {broadcast_addr}: {e}")

        except Exception as e:
            logging.error(f"Error sending immediate broadcast: {e}")
        finally:
             if temp_sock:
                 temp_sock.close()

    def stop(self):
        self.running = False
        logging.info("PeerDiscovery stopping...")
        if self._send_socket:
             self._send_socket.close()
             self._send_socket = None
        if self._receive_socket:
             self._receive_socket.close()
             self._receive_socket = None