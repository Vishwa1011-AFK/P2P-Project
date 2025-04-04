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

    async def send_broadcasts(self):
        logging.info("Starting broadcast sender task.")
        while self.running and not shutdown_event.is_set():
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

                own_ip = await get_own_ip()
                if not own_ip:
                     logging.warning("Could not determine own IP for broadcast.")
                     await asyncio.sleep(self.broadcast_interval)
                     continue

                username = user_data.get("original_username", "unknown")
                device_id = user_data.get("device_id", "unknown") 

                message = json.dumps({
                    "ip": own_ip,
                    "username": username,
                    "device_id": device_id 
                }).encode()

                broadcast_sent = False

                for interface in netifaces.interfaces():
                    try:
                        if netifaces.AF_INET in netifaces.ifaddresses(interface):
                            addrs = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                            if addrs:
                                broadcast_addr = addrs[0].get("broadcast")
                                if broadcast_addr:

                                    sock.sendto(message, (broadcast_addr, self.broadcast_port))
                                    logging.debug(f"Broadcast sent on {interface} to {broadcast_addr}:{self.broadcast_port}")
                                    broadcast_sent = True
                    except OSError as e:
                         logging.debug(f"OS error broadcasting on {interface}: {e}")
                    except KeyError:
                         logging.debug(f"Could not find IPv4 or broadcast address details for {interface}")
                    except Exception as e:
                        logging.debug(f"Unexpected error broadcasting on interface {interface}: {e}")

                if not broadcast_sent:
                    logging.warning("Could not successfully broadcast discovery message on any interface.")

            except socket.error as sock_err:
                 logging.error(f"Socket error during broadcast setup or sending: {sock_err}")
            except Exception as e:
                logging.error(f"Error in broadcast task main loop: {e}")
            finally:
                if sock:
                    sock.close() 

            try:
                await asyncio.sleep(self.broadcast_interval)
            except asyncio.CancelledError:
                logging.info("Broadcast sender task cancelled during sleep.")
                break 

        logging.info("send_broadcasts task stopped.")

    def stop(self): 
        self.running = False

    async def receive_broadcasts(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
             sock.bind(("", self.broadcast_port))
        except OSError as e:
            logging.critical(f"Could not bind discovery receive socket to port {self.broadcast_port}: {e}")
            self.running = False 
            return 
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        own_ip = await get_own_ip()
        try:
            while self.running and not shutdown_event.is_set():
                try:
                    data, (sender_ip, _) = await loop.sock_recvfrom(sock, 1024)
                    if sender_ip == own_ip:
                        continue
                    message = json.loads(data.decode())
                    peer_ip = message["ip"]
                    username = message["username"]
                    self.peer_list[peer_ip] = (username, asyncio.get_event_loop().time())
                except json.JSONDecodeError:
                    logging.warning(f"Invalid JSON broadcast received from {sender_ip}")
                except KeyError:
                     logging.warning(f"Malformed broadcast received from {sender_ip} (missing fields)")
                except UnicodeDecodeError:
                    logging.warning(f"Non-UTF8 broadcast received from {sender_ip}")
                except asyncio.CancelledError:
                     raise # Propagate cancellation
                except BlockingIOError:
                     await asyncio.sleep(0.1) # No data available, wait briefly
                except OSError as e:
                     logging.error(f"Network error receiving broadcast: {e}")
                     await asyncio.sleep(1) # Wait longer after network error
                except Exception as e:
                    logging.exception(f"Unexpected error receiving broadcast: {e}")
                    await asyncio.sleep(0.5) # Wait before retrying

        finally:
            sock.close()
        logging.info("receive_broadcasts stopped.")

    async def cleanup_stale_peers(self):
        while self.running and not shutdown_event.is_set():
            try:
                current_time = asyncio.get_event_loop().time()
                stale_peers = []
                for peer_ip, (_, last_seen) in self.peer_list.items():
                    if current_time - last_seen > self.cleanup_interval:
                         stale_peers.append(peer_ip)

                for peer_ip in stale_peers:
                    if peer_ip in self.peer_list: # Check again in case updated
                        del self.peer_list[peer_ip]
                        logging.info(f"Removed stale peer: {peer_ip}")

            except Exception as e:
                 logging.exception(f"Error during stale peer cleanup: {e}")

            await asyncio.sleep(self.cleanup_interval)
        logging.info("cleanup_stale_peers stopped.")

    async def send_immediate_broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            own_ip = await get_own_ip()
            username = user_data.get("original_username", "unknown")
            message = json.dumps({"ip": own_ip, "username": username}).encode()
            for interface in netifaces.interfaces():
                try:
                    if netifaces.AF_INET in netifaces.ifaddresses(interface):
                         addrs = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                         if addrs:
                             broadcast_addr = addrs[0].get("broadcast")
                             if broadcast_addr:
                                 sock.sendto(message, (broadcast_addr, self.broadcast_port))
                except OSError as e:
                     logging.debug(f"Network error broadcasting on {interface}: {e}")
                except KeyError:
                     logging.debug(f"Could not find broadcast address for {interface}")
                except Exception as e:
                    logging.debug(f"Unexpected error broadcasting on {interface}: {e}")
        except Exception as e:
            logging.error(f"Error sending immediate broadcast: {e}")
        finally:
            sock.close()

    def stop(self):
        self.running = False