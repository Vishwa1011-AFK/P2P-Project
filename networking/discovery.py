import asyncio
import socket
import json
import logging
import netifaces
import sys # For platform check

from .shared_state import shutdown_event
from .utils import get_own_ip # Keep using utils

logger = logging.getLogger(__name__)

class PeerDiscovery:
    """Handles discovering peers on the local network using UDP broadcasts."""
    def __init__(self, broadcast_port=37020, broadcast_interval=5, cleanup_interval=60):
        """
        Args:
            broadcast_port: UDP port for discovery messages.
            broadcast_interval: Seconds between sending broadcasts.
            cleanup_interval: Seconds after which unseen peers are removed.
        """
        self.broadcast_port = broadcast_port
        self.peer_list = {}  # {ip: (username, last_seen_timestamp)}
        self.broadcast_interval = broadcast_interval
        self.cleanup_interval = cleanup_interval
        self.running = True # Flag to control running loops
        self._broadcast_socket = None # Socket for sending
        self._receive_socket = None   # Socket for receiving
        logger.debug(f"PeerDiscovery initialized: Port={broadcast_port}, Interval={broadcast_interval}, Cleanup={cleanup_interval}")

    # --- Sending Broadcasts ---

    def _get_broadcast_addresses(self):
        """Get a list of potential broadcast addresses for all suitable interfaces."""
        addresses = set() # Use set to avoid duplicates
        try:
            for interface in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ipv4_info = addrs[netifaces.AF_INET][0]
                        # Ensure 'broadcast' key exists, crucial for some platforms/interfaces
                        if 'broadcast' in ipv4_info:
                             addr = ipv4_info['broadcast']
                             # Basic validation: is it a plausible IPv4 broadcast address?
                             if isinstance(addr, str) and '.' in addr:
                                  addresses.add(addr)
                             # else:
                             #     logger.debug(f"Ignoring invalid broadcast address '{addr}' on interface {interface}")
                        # else:
                        #     # Log interfaces without broadcast addr only if debugging discovery issues
                        #     logger.debug(f"Interface {interface} lacks a broadcast address in netifaces info.")
                except KeyError:
                     logger.debug(f"Could not get address info for interface {interface} (KeyError).")
                except Exception as e:
                    # Log other errors getting info for a specific interface
                    logger.warning(f"Error getting address info for interface {interface}: {e}")
        except Exception as e:
            logger.error(f"Error iterating network interfaces: {e}", exc_info=True)
            # Fallback if netifaces fails completely? Use limited broadcast?
            logger.warning("Falling back to limited broadcast address 255.255.255.255")
            addresses.add("255.255.255.255")

        if not addresses:
             logger.warning("Could not find any broadcast addresses! Discovery sending may fail.")
             # Add limited broadcast as last resort if empty
             addresses.add("255.255.255.255")

        return list(addresses)


    async def send_broadcasts(self, config_manager):
        """Coroutine to periodically send UDP broadcasts announcing presence."""
        logger.info(f"Broadcast sender task starting (Interval: {self.broadcast_interval}s).")
        try:
            # Create UDP socket for sending
            self._broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            # Set socket options: enable broadcast
            self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # SO_REUSEADDR might be needed on some systems if restarting quickly.
            # It allows binding to an address/port that is in TIME_WAIT state.
            # For sending, it's less critical than for receiving, but can help avoid "address already in use".
            try:
                 if hasattr(socket, "SO_REUSEADDR"):
                      self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                 # SO_REUSEPORT allows multiple processes/sockets to bind to the *same* address/port
                 # for load balancing (mainly UDP). Not strictly necessary here, but doesn't hurt.
                 # if hasattr(socket, "SO_REUSEPORT") and sys.platform != 'win32': # REUSEPORT might behave differently/be unavailable on Windows
                 #      self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError as e:
                 logger.warning(f"Could not set socket REUSEADDR/REUSEPORT option: {e}")

            # Optionally bind the sending socket to a specific interface/IP?
            # Not usually necessary for sending broadcasts, OS chooses appropriate interface.
            # self._broadcast_socket.bind((config_manager.get_ip(), 0)) # Bind to specific IP, random port

        except Exception as sock_err:
            logger.critical(f"Failed to create or configure broadcast sender socket: {sock_err}", exc_info=True)
            self._broadcast_socket = None # Ensure it's None if setup failed
            return # Exit task if socket fails

        while self.running and not shutdown_event.is_set():
            next_run_time = asyncio.get_event_loop().time() + self.broadcast_interval
            try:
                # Get current user info from ConfigManager
                own_ip = config_manager.get_ip()
                username = config_manager.get_username()

                # Don't broadcast if essential info is missing
                if not username or username == "UnknownUser" or own_ip == "127.0.0.1":
                     logger.warning("Username or valid IP not available, delaying broadcast.")
                     # Wait full interval before retrying
                     await asyncio.sleep(max(0, next_run_time - asyncio.get_event_loop().time()))
                     continue

                # Construct message payload
                message_payload = {"ip": own_ip, "username": username}
                message_bytes = json.dumps(message_payload).encode('utf-8')

                # Get list of broadcast addresses to send to
                broadcast_addrs = self._get_broadcast_addresses()
                # logger.debug(f"Sending broadcast to addresses: {broadcast_addrs}")

                for addr in broadcast_addrs:
                    try:
                        # Send to each broadcast address on the discovery port
                        self._broadcast_socket.sendto(message_bytes, (addr, self.broadcast_port))
                        # logger.debug(f"Broadcast sent to {addr}:{self.broadcast_port}")
                    except socket.error as send_err:
                         # Log common, potentially harmless errors at debug level
                         if "Network is unreachable" in str(send_err) or "Host is down" in str(send_err):
                              logger.debug(f"Cannot send broadcast to {addr}: {send_err}")
                         else: # Log other socket errors more visibly
                              logger.warning(f"Socket error sending broadcast to {addr}: {send_err}")
                    except Exception as e:
                        logger.warning(f"Unexpected error sending broadcast to {addr}: {e}")

            except asyncio.CancelledError:
                 logger.info("Broadcast sender task cancelled.")
                 break # Exit loop immediately
            except Exception as e:
                 logger.exception(f"Error in broadcast sender task loop: {e}")
                 # Avoid tight loop on error, wait before retrying

            # Wait until the next scheduled broadcast time
            await asyncio.sleep(max(0, next_run_time - asyncio.get_event_loop().time()))

        # --- Cleanup ---
        if self._broadcast_socket:
            logger.debug("Closing broadcast sender socket.")
            self._broadcast_socket.close()
            self._broadcast_socket = None
        logger.info("Broadcast sender task stopped.")


    # --- Receiving Broadcasts ---

    async def receive_broadcasts(self):
        """Coroutine to listen for UDP broadcasts from peers."""
        logger.info(f"Broadcast receiver task starting (Port: {self.broadcast_port}).")
        try:
            # Create UDP socket for receiving
            # Use getaddrinfo for potentially more robust address family/type determination
            # Listen on all interfaces ('')
            addr_info_list = socket.getaddrinfo(None, self.broadcast_port, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if not addr_info_list:
                 logger.critical("Could not get address info for UDP receiver binding.")
                 return
            addr_info = addr_info_list[0] # Use the first suitable result

            self._receive_socket = socket.socket(addr_info[0], addr_info[1], addr_info[2])

            # Set socket options: Allow reuse of address/port
            # Crucial for UDP servers restarting quickly or multiple listeners (if using REUSEPORT)
            try:
                if hasattr(socket, "SO_REUSEADDR"):
                     self._receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # if hasattr(socket, "SO_REUSEPORT") and sys.platform != 'win32':
                #     self._receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError as e:
                 logger.warning(f"Could not set socket REUSEADDR/REUSEPORT option for receiver: {e}")

            # Bind the socket to listen on all interfaces for the discovery port
            self._receive_socket.bind(addr_info[4]) # addr_info[4] is the sockaddr tuple
            self._receive_socket.setblocking(False) # Use non-blocking with asyncio
            logger.info(f"Broadcast receiver bound to {addr_info[4]}")

        except Exception as sock_err:
            logger.critical(f"Failed to create or bind broadcast receiver socket: {sock_err}", exc_info=True)
            self._receive_socket = None
            return

        loop = asyncio.get_event_loop()
        own_ip = await get_own_ip() # Get own IP once to filter self-broadcasts

        while self.running and not shutdown_event.is_set():
            try:
                # Use loop.sock_recvfrom for asynchronous receiving
                data, addr = await loop.sock_recvfrom(self._receive_socket, 1500) # Buffer size, 1500 typical MTU
                sender_ip = addr[0]
                sender_port = addr[1] # Port can be useful for debugging

                # Ignore self-broadcasts
                if sender_ip == own_ip:
                    # logger.debug("Ignored self-broadcast")
                    continue

                # Decode and parse message safely
                try:
                    message_str = data.decode('utf-8')
                    message = json.loads(message_str)
                except (UnicodeDecodeError, json.JSONDecodeError) as decode_err:
                    logger.warning(f"Invalid broadcast format received from {sender_ip}:{sender_port}: {decode_err} - Data: {data[:100]!r}")
                    continue # Skip invalid message

                # Extract info, validate content
                peer_ip_in_msg = message.get("ip")
                username = message.get("username")

                if not peer_ip_in_msg or not username or not isinstance(username, str):
                    logger.warning(f"Invalid broadcast content from {sender_ip}:{sender_port}: {message_str}")
                    continue

                # Use sender_ip from socket addr as the key, more reliable than message content IP
                current_time = loop.time()
                peer_key = sender_ip

                # Update peer list, log if new or changed
                existing_entry = self.peer_list.get(peer_key)
                if not existing_entry or existing_entry[0] != username:
                     logger.info(f"Discovered/Updated peer: {username} ({peer_key})")

                self.peer_list[peer_key] = (username, current_time)

            except asyncio.CancelledError:
                 logger.info("Broadcast receiver task cancelled.")
                 break # Exit loop immediately
            except BlockingIOError:
                 # This is expected if no data is available on non-blocking socket
                 await asyncio.sleep(0.1) # Sleep briefly before trying recv again
            except Exception as e:
                 logger.error(f"Error receiving broadcast: {e}", exc_info=True)
                 # Avoid tight loop on unexpected errors
                 await asyncio.sleep(0.5)

        # --- Cleanup ---
        if self._receive_socket:
            logger.debug("Closing broadcast receiver socket.")
            self._receive_socket.close()
            self._receive_socket = None
        logger.info("Broadcast receiver task stopped.")

    # --- Peer List Cleanup ---

    async def cleanup_stale_peers(self):
        """Coroutine to periodically remove peers not seen recently."""
        logger.info(f"Peer cleanup task starting (Interval: {self.cleanup_interval}s).")
        # Add a grace period multiplier to the cleanup interval
        stale_threshold = self.cleanup_interval * 1.5
        try:
            while self.running and not shutdown_event.is_set():
                # Wait for the cleanup interval first
                await asyncio.sleep(self.cleanup_interval)

                current_time = asyncio.get_event_loop().time()
                stale_peers_to_remove = []
                # Iterate over a copy of keys in case dict changes during check (less likely here)
                for peer_ip, (username, last_seen) in list(self.peer_list.items()):
                    if current_time - last_seen > stale_threshold:
                        stale_peers_to_remove.append(peer_ip)

                if stale_peers_to_remove:
                    logger.debug(f"Cleaning up {len(stale_peers_to_remove)} stale discovered peers.")
                    for peer_ip in stale_peers_to_remove:
                         # Remove safely using pop with default
                         username, _ = self.peer_list.pop(peer_ip, ("Unknown", 0))
                         logger.info(f"Removed stale discovered peer: {username} ({peer_ip})")
        except asyncio.CancelledError:
            logger.info("Peer cleanup task cancelled.")
        except Exception as e:
             logger.exception(f"Error in peer cleanup task loop: {e}")
             # Avoid tight loop on error
             await asyncio.sleep(self.cleanup_interval)
        finally:
            logger.info("Peer cleanup task stopped.")

    # --- Immediate Broadcast ---

    async def send_immediate_broadcast(self, config_manager):
        """Send an immediate broadcast, e.g., after username change."""
        if not self._broadcast_socket:
            logger.warning("Cannot send immediate broadcast, sender socket not ready.")
            return
        if not self.running:
             logger.warning("Cannot send immediate broadcast, discovery stopped.")
             return

        logger.info("Sending immediate broadcast announcement.")
        try:
            own_ip = config_manager.get_ip()
            username = config_manager.get_username()
            if not username or username == "UnknownUser" or own_ip == "127.0.0.1":
                 logger.warning("Cannot send immediate broadcast: Username or IP not valid.")
                 return

            message_payload = {"ip": own_ip, "username": username}
            message_bytes = json.dumps(message_payload).encode('utf-8')

            broadcast_addrs = self._get_broadcast_addresses()
            logger.debug(f"Sending immediate broadcast to: {broadcast_addrs}")
            for addr in broadcast_addrs:
                try:
                    self._broadcast_socket.sendto(message_bytes, (addr, self.broadcast_port))
                except socket.error as send_err:
                     logger.debug(f"Socket error sending immediate broadcast to {addr}: {send_err}")
                except Exception as e:
                     logger.warning(f"Error sending immediate broadcast to {addr}: {e}")
        except Exception as e:
            logger.error(f"Failed to prepare or send immediate broadcast: {e}", exc_info=True)

    # --- Accessor & Control ---

    def get_peer_list(self):
        """Return a copy of the current discovered peer list."""
        # Return a copy to prevent external modification
        return self.peer_list.copy()

    def stop(self):
        """Stop the discovery sending and receiving loops."""
        logger.info("Stopping PeerDiscovery tasks...")
        self.running = False # Signal loops to stop
        # Close sockets to potentially interrupt blocking calls (like sock_recvfrom)
        if self._broadcast_socket:
            self._broadcast_socket.close() # Close sender
            self._broadcast_socket = None
        if self._receive_socket:
            self._receive_socket.close() # Close receiver
            self._receive_socket = None
        logger.debug("Discovery sockets closed.")