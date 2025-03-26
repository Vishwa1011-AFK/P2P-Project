# networking/peer_manager.py
import asyncio
import logging
import json
import websockets
from cryptography.hazmat.primitives import serialization
from .shared_state import shutdown_event

logger = logging.getLogger(__name__)

class PeerManager:
    def __init__(self, config_manager, ui_manager):
        """
        Initializes the PeerManager.
        Args:
            config_manager: Instance of ConfigManager.
            ui_manager: Instance of UIManager.
        """
        self.config_manager = config_manager
        self.ui_manager = ui_manager
        self.transfer_manager = None # Must be set later via property or method

        # Peer state - Use private attributes and provide getters if needed
        self._connections = {} # {peer_ip: websocket}
        self._peer_usernames = {} # {username: peer_ip}
        self._peer_public_keys = {} # {peer_ip: public_key_object}
        self._discovered_peers = {} # {ip: (username, last_seen)} - Populated by discovery task

        # Connection Approval State
        self._pending_connection_approvals = {} # {peer_ip: asyncio.Future}

        logger.debug("PeerManager initialized.")

    @property
    def transfer_manager(self):
        return self._transfer_manager

    @transfer_manager.setter
    def transfer_manager(self, manager):
        """Set the TransferManager instance, needed for cleanup on disconnect."""
        logger.debug("TransferManager instance set in PeerManager.")
        self._transfer_manager = manager

    async def _queue_ui_message(self, message):
        """Helper to safely queue messages for the UI Manager."""
        if self.ui_manager:
            await self.ui_manager.add_message(message)
        else:
            # Fallback if UI manager isn't fully initialized yet
            print(f"[PeerManager Log] {message}")
            logger.warning("UIManager not available in PeerManager to queue message.")

    # --- State Accessors (Read-only access preferred) ---

    def is_connected(self, peer_ip=None, username=None):
        """Check if a peer is currently connected by IP or username."""
        if username:
            peer_ip = self._peer_usernames.get(username)
        return peer_ip in self._connections

    def get_websocket(self, peer_ip=None, username=None):
        """Get the websocket object for a connected peer."""
        if username and not peer_ip:
            peer_ip = self._peer_usernames.get(username)
        ws = self._connections.get(peer_ip)
        # Optional: Check if websocket is still open before returning
        # if ws and not ws.open:
        #    logger.warning(f"Websocket for {peer_ip} found but is not open.")
        #    # Consider triggering cleanup here? Or rely on maintenance task.
        #    return None
        return ws

    def get_peer_ip(self, username):
        """Get the IP address associated with a connected username."""
        return self._peer_usernames.get(username)

    def get_peer_username(self, peer_ip):
         """Get the username associated with a connected IP address."""
         # Reverse lookup - potentially slow if many peers, consider an inverse map if needed often
         return next((uname for uname, ip in self._peer_usernames.items() if ip == peer_ip), None)

    def get_public_key(self, peer_ip):
         """Get the public key object for a connected peer IP."""
         return self._peer_public_keys.get(peer_ip)

    def get_all_connected_peers(self):
        """Returns a list of (username, ip) tuples for currently connected peers."""
        # Return a copy to prevent modification of internal state
        return list(self._peer_usernames.items())

    def get_discovered_peers(self):
        """Returns a copy of the cache of discovered peers."""
        # Return a copy
        return self._discovered_peers.copy()

    # --- State Modification (Add/Remove Peers) ---

    async def add_peer(self, peer_ip, username, public_key, websocket):
        """
        Adds a fully handshaked peer to the managed state.
        Called by connection.py after successful handshake.
        """
        if peer_ip == self.config_manager.get_ip():
            logger.warning("Attempted to add self as peer.")
            return
        if peer_ip in self._connections:
            logger.warning(f"Peer {peer_ip} ({username}) already connected. Closing duplicate connection.")
            # Close the new duplicate websocket immediately
            if websocket and websocket.open:
                try:
                    await websocket.close(code=1008, reason="Duplicate connection")
                except Exception as e:
                    logger.error(f"Error closing duplicate websocket for {peer_ip}: {e}")
            return

        logger.info(f"Adding peer: {username} ({peer_ip})")
        self._connections[peer_ip] = websocket
        self._peer_public_keys[peer_ip] = public_key

        # Handle potential username conflicts gracefully
        existing_ip_for_name = self._peer_usernames.get(username)
        if existing_ip_for_name and existing_ip_for_name != peer_ip:
            logger.warning(f"Username conflict: '{username}' is already used by {existing_ip_for_name}. Disconnecting older peer.")
            await self.remove_peer(existing_ip_for_name, f"Username conflict with new peer {peer_ip}")

        self._peer_usernames[username] = peer_ip

        await self._queue_ui_message(f"*** Connected to {username} ({peer_ip}) ***")

    async def remove_peer(self, peer_ip, reason="Unknown reason"):
        """
        Removes a peer and cleans up all associated state (connections, keys, transfers).
        This is the central cleanup function.
        """
        username = self.get_peer_username(peer_ip) # Get username before potentially removing it
        display_name = username or f"Peer_{peer_ip}"

        if peer_ip not in self._connections and not username:
            logger.debug(f"Attempted to remove non-existent or already removed peer: {display_name}")
            return # Already removed or never fully added

        logger.info(f"Removing peer {display_name}. Reason: {reason}")

        # 1. Close WebSocket connection
        websocket = self._connections.pop(peer_ip, None)
        if websocket and websocket.open:
            try:
                close_code = 1000 if reason == "User disconnected" else 1001 # 1000=Normal, 1001=Going Away
                # Ensure reason is not too long for WebSocket close frame
                safe_reason = reason[:123]
                await websocket.close(code=close_code, reason=safe_reason)
                logger.debug(f"Closed WebSocket for {display_name}")
            except websockets.exceptions.ConnectionClosed:
                logger.debug(f"WebSocket for {display_name} was already closing.")
            except Exception as e:
                logger.error(f"Error closing WebSocket for {display_name}: {e}")

        # 2. Remove from state dictionaries
        self._peer_public_keys.pop(peer_ip, None)
        if username and self._peer_usernames.get(username) == peer_ip:
             # Only remove username mapping if it points to the peer being removed
             self._peer_usernames.pop(username, None)
             logger.debug(f"Removed username mapping for {username}")

        # 3. Cancel/Fail associated file transfers (Notify TransferManager)
        if self.transfer_manager:
            try:
                await self.transfer_manager.cleanup_peer_transfers(peer_ip)
                logger.debug(f"Notified TransferManager to clean up transfers for {display_name}")
            except Exception as e:
                 logger.error(f"Error during TransferManager cleanup for peer {display_name}: {e}")

        # 4. Remove any pending connection approval (should be rare here, but good practice)
        future = self._pending_connection_approvals.pop(peer_ip, None)
        if future and not future.done():
             logger.warning(f"Removed pending connection approval for {display_name} during disconnection.")
             future.cancel() # Cancel the future if it was still pending

        # 5. Queue UI message
        await self._queue_ui_message(f"*** {display_name} disconnected ({reason}) ***")
        logger.info(f"Finished removing peer {display_name}")

    # --- Connection Approval ---
    def add_pending_connection_approval(self, peer_ip, future):
        """Stores the future associated with a pending connection request."""
        logger.debug(f"Adding pending connection approval future for {peer_ip}")
        self._pending_connection_approvals[peer_ip] = future

    def get_pending_connection_approval_future(self, peer_ip):
        """Gets the future for a specific pending approval."""
        return self._pending_connection_approvals.get(peer_ip)

    def resolve_pending_connection_approval(self, peer_ip, approved):
        """Sets the result of a pending connection approval future. Called by UIManager."""
        future = self._pending_connection_approvals.pop(peer_ip, None)
        if future and not future.done():
            logger.info(f"Resolving connection approval for {peer_ip} as {approved}")
            future.set_result(approved)
            return True
        elif future:
             logger.warning(f"Attempted to resolve already completed connection future for {peer_ip}")
        else:
             logger.warning(f"No pending connection approval future found for {peer_ip} to resolve.")
        return False

    # --- Username Change Handling ---
    async def notify_username_change(self, old_username, new_username):
        """Send USERNAME_UPDATE message to all connected peers."""
        message = json.dumps({
            "type": "USERNAME_UPDATE",
            "old_username": old_username,
            "new_username": new_username
        })
        logger.info(f"Notifying connected peers of username change: {old_username} -> {new_username}")
        # Send to all currently connected peers
        # Iterate over a copy of items in case remove_peer is called concurrently
        for peer_ip, websocket in list(self._connections.items()):
             # Check websocket validity before sending
             if websocket and websocket.open:
                  try:
                       await websocket.send(message)
                       logger.debug(f"Sent username update to {peer_ip}")
                  except websockets.exceptions.ConnectionClosed as e:
                       logger.warning(f"Failed to send username update to {peer_ip}: Connection closed ({e.code}). Removing peer.")
                       # Remove peer if connection closed during send attempt
                       await self.remove_peer(peer_ip, f"Connection closed during username update send: {e.code}")
                  except Exception as e:
                       logger.error(f"Failed to send username update to {peer_ip}: {e}")
                       # Consider removing peer if send fails repeatedly or for critical errors? Optional.
                       # await self.remove_peer(peer_ip, f"Failed sending username update: {e}")
             else:
                 # This case should ideally be rare if maintenance is working, but handle defensively
                 logger.warning(f"Skipping username update send to {peer_ip}: Websocket invalid or closed.")
                 if peer_ip in self._connections: # Check if it's still in our dict despite being closed
                      await self.remove_peer(peer_ip, "Websocket found closed during username update send")


    def handle_username_update(self, peer_ip, old_username, new_username):
        """
        Update internal state when a peer announces a username change.
        Called by protocol.py when a USERNAME_UPDATE message is received.
        """
        logger.info(f"Handling username update message from {peer_ip}: {old_username} -> {new_username}")
        current_ip_mapped_to_old_name = self._peer_usernames.get(old_username)

        if current_ip_mapped_to_old_name == peer_ip:
             # This is the expected case: the peer sending the update owns the old username
             # Remove old mapping
             del self._peer_usernames[old_username]
             # Add new mapping
             self._peer_usernames[new_username] = peer_ip
             logger.info(f"Peer {peer_ip} successfully changed username from '{old_username}' to '{new_username}'.")
             asyncio.create_task(self._queue_ui_message(f"*** Peer '{old_username}' is now known as '{new_username}' ***"))
             # TODO: Trigger update/refresh of the TUI completer if possible?
             # If UIManager exposes a method: self.ui_manager.refresh_completer()
        elif current_ip_mapped_to_old_name:
            # The old_username belongs to a *different* connected peer. This could indicate a conflict
            # or a stale message. Log a warning and potentially ignore.
            logger.warning(f"Received username update from {peer_ip} for '{old_username}', but that name currently maps to a different IP ({current_ip_mapped_to_old_name}). Ignoring update for '{old_username}'.")
            # Still, check if the *new* username conflicts
            existing_ip_for_new_name = self._peer_usernames.get(new_username)
            if existing_ip_for_new_name and existing_ip_for_new_name != peer_ip:
                 logger.warning(f"New username '{new_username}' from {peer_ip} conflicts with existing peer {existing_ip_for_new_name}. Update ignored.")
            elif peer_ip in self._connections: # If the peer is connected, map their new username even if old was weird
                 self._peer_usernames[new_username] = peer_ip
                 logger.info(f"Peer {peer_ip} announced new username '{new_username}' (old name '{old_username}' mapping was inconsistent).")
                 asyncio.create_task(self._queue_ui_message(f"*** Peer {peer_ip} announced username '{new_username}' (was '{old_username}') ***"))

        else:
            # If old_username wasn't known, treat it as the peer simply announcing their name.
            # Check for conflict with the new name.
            existing_ip_for_new_name = self._peer_usernames.get(new_username)
            if existing_ip_for_new_name and existing_ip_for_new_name != peer_ip:
                 logger.warning(f"Peer {peer_ip} announced username '{new_username}', which conflicts with existing peer {existing_ip_for_new_name}. Ignoring.")
            elif peer_ip in self._connections: # Only add if the peer is actually connected
                 self._peer_usernames[new_username] = peer_ip
                 logger.info(f"Peer {peer_ip} announced username '{new_username}' (was previously unknown).")
                 asyncio.create_task(self._queue_ui_message(f"*** Peer {peer_ip} announced username '{new_username}' ***"))

    # --- Maintenance Task ---
    async def run_maintenance(self, discovery_instance, interval=10):
        """Periodically update discovery list cache and check connection health."""
        logger.info("Peer maintenance task started.")
        while not shutdown_event.is_set():
            next_run_time = asyncio.get_event_loop().time() + interval
            try:
                # Update discovered peers list cache from discovery instance
                if discovery_instance:
                    self._discovered_peers = discovery_instance.get_peer_list() # Assuming get_peer_list method exists
                else:
                     logger.warning("Discovery instance not available in maintenance task.")

                # Check active connections using ping
                disconnected_peers_info = [] # Store tuples of (ip, reason)
                # Iterate over a copy of items in case remove_peer modifies the dict
                for peer_ip, websocket in list(self._connections.items()):
                    if shutdown_event.is_set(): break # Check shutdown flag frequently
                    if not websocket or not websocket.open:
                        # Found an inconsistency - websocket closed but still in our list?
                        logger.warning(f"Found closed websocket for {peer_ip} during maintenance check. Marking for removal.")
                        disconnected_peers_info.append((peer_ip, "Websocket found closed"))
                        continue
                    try:
                        # Send ping and wait for pong implicitly handled by library on next operation or timeout
                        await asyncio.wait_for(websocket.ping(), timeout=5.0)
                        # logger.debug(f"Ping sent successfully to {peer_ip}")
                    except asyncio.TimeoutError:
                        logger.warning(f"Ping timeout for {peer_ip}. Marking for removal.")
                        disconnected_peers_info.append((peer_ip, "Ping timeout"))
                    except websockets.exceptions.ConnectionClosed:
                        # Connection closed between check and ping attempt
                        logger.warning(f"Connection closed for {peer_ip} before/during ping. Marking for removal.")
                        disconnected_peers_info.append((peer_ip, "Connection closed during ping"))
                    except ConnectionResetError:
                         logger.warning(f"Connection reset for {peer_ip} during ping. Marking for removal.")
                         disconnected_peers_info.append((peer_ip, "Connection reset"))
                    except Exception as e:
                         # Catch other potential errors during ping
                         logger.error(f"Unexpected error pinging {peer_ip}: {e}")
                         disconnected_peers_info.append((peer_ip, f"Ping error: {e}"))


                # Process disconnections outside the iteration loop
                if disconnected_peers_info:
                    logger.debug(f"Processing {len(disconnected_peers_info)} disconnections found during maintenance.")
                    # Run removals concurrently for efficiency
                    removal_tasks = [self.remove_peer(peer_ip, reason) for peer_ip, reason in disconnected_peers_info]
                    await asyncio.gather(*removal_tasks, return_exceptions=True) # Log exceptions from gather if needed

                # Wait until the next scheduled run time
                await asyncio.sleep(max(0, next_run_time - asyncio.get_event_loop().time()))

            except asyncio.CancelledError:
                logger.info("Peer maintenance task cancelled.")
                break
            except Exception as e:
                logger.exception(f"Error in peer maintenance task loop: {e}")
                # Avoid tight loop on error, wait for the planned interval before retrying
                await asyncio.sleep(interval)
        logger.info("Peer maintenance task stopped.")