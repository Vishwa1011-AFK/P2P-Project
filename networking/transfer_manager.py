import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
from enum import Enum
from .shared_state import shutdown_event # Use shared shutdown event
import websockets # For exception types

logger = logging.getLogger(__name__)

class TransferState(Enum):
    PENDING_APPROVAL = "pending_approval" # Receiver waiting for user
    WAITING_ACK = "waiting_ack"         # Sender waiting for receiver approval ACK
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"                   # Receiver denied or sender timed out waiting for ACK

class FileTransfer:
    """Represents an active file transfer and its state."""
    def __init__(self, peer_ip, direction, transfer_id, total_size,
                 local_path=None, remote_rel_path=None, expected_hash=None):
        """
        Args:
            peer_ip: IP address of the peer involved.
            direction: "send" or "receive".
            transfer_id: Unique ID for the transfer.
            total_size: Total size of the file in bytes.
            local_path: Full local path for sending (source) or receiving (destination).
            remote_rel_path: Relative path used in protocol/display (e.g., "folder/file.txt").
            expected_hash: Expected SHA-256 hash of the file (hex string).
        """
        self.peer_ip = peer_ip
        self.direction = direction
        self.transfer_id = transfer_id
        self.total_size = total_size
        self.local_path = local_path
        self.remote_rel_path = remote_rel_path or os.path.basename(local_path or "unknown_file")
        self.expected_hash = expected_hash

        self.transferred_size = 0
        self.file_handle = None # aiofiles handle
        self.hash_algo = hashlib.sha256() if expected_hash else None
        # Initial state depends on direction
        self.state = TransferState.PENDING_APPROVAL if direction == "receive" else TransferState.WAITING_ACK
        self.condition = asyncio.Condition() # For pause/resume coordination

        logger.debug(f"Transfer object created: {self.transfer_id} ({self.direction} '{self.remote_rel_path}' from/to {self.peer_ip}) State: {self.state.value}")

    async def pause(self):
        """Pause the transfer if it's in progress."""
        async with self.condition:
            if self.state == TransferState.IN_PROGRESS:
                self.update_state(TransferState.PAUSED) # Use method to log change
                logger.info(f"Transfer {self.transfer_id} paused.")
                return True
            else:
                logger.warning(f"Cannot pause transfer {self.transfer_id} in state {self.state.value}")
                return False

    async def resume(self):
        """Resume the transfer if it's paused."""
        async with self.condition:
            if self.state == TransferState.PAUSED:
                self.update_state(TransferState.IN_PROGRESS) # Use method to log change
                # Notify potentially waiting chunk sender/receiver task
                self.condition.notify_all()
                logger.info(f"Transfer {self.transfer_id} resumed.")
                return True
            else:
                 logger.warning(f"Cannot resume transfer {self.transfer_id} in state {self.state.value}")
                 return False

    def update_state(self, new_state):
        """Update transfer state and log the change."""
        if self.state != new_state:
             old_state_val = self.state.value
             self.state = new_state
             logger.info(f"Transfer {self.transfer_id} state change: {old_state_val} -> {self.state.value}")
             # Optional: Trigger actions based on state change (e.g., close handle on FAILED)
             # if new_state in (TransferState.FAILED, TransferState.DENIED, TransferState.COMPLETED):
             #    asyncio.create_task(self.close_handle()) # Schedule cleanup

    async def close_handle(self):
        """Safely close the file handle if it's open."""
        if self.file_handle and not self.file_handle.closed:
            handle_path = self.local_path # Store path before handle is closed/nulled
            try:
                await self.file_handle.close()
                logger.debug(f"Closed file handle for transfer {self.transfer_id} ({handle_path})")
            except Exception as e:
                logger.error(f"Error closing file handle for transfer {self.transfer_id} ({handle_path}): {e}")
            finally:
                self.file_handle = None # Ensure handle is cleared


class TransferManager:
    """Manages active file transfers, approvals, and progress."""
    def __init__(self, peer_manager, ui_manager):
        """
        Initializes the TransferManager.
        Args:
            peer_manager: Instance of PeerManager.
            ui_manager: Instance of UIManager.
        """
        self.peer_manager = peer_manager
        self.ui_manager = ui_manager
        self._active_transfers = {} # {transfer_id: FileTransfer}

        # Futures for coordinating asynchronous approval steps
        # Receiver waits for UI 'yes'/'no' via UIManager -> resolves this future
        self._pending_receive_approvals = {} # {transfer_id: asyncio.Future}
        # Sender waits for 'file_transfer_ack' message -> resolves this future
        self._pending_send_acks = {} # {transfer_id: asyncio.Future}

        logger.debug("TransferManager initialized.")

    async def _queue_ui_message(self, message):
        """Helper to safely queue messages for the UI Manager."""
        if self.ui_manager:
            await self.ui_manager.add_message(message)
        else:
            print(f"[TransferManager Log] {message}")
            logger.warning("UIManager not available in TransferManager to queue message.")

    async def _compute_hash(self, file_path):
        """Compute the SHA-256 hash of a file asynchronously."""
        # Consider moving this to utils.py if used elsewhere
        hash_algo = hashlib.sha256()
        try:
            async with aiofiles.open(file_path, "rb") as f:
                while True:
                    chunk = await f.read(1024 * 1024) # Read 1MB chunks
                    if not chunk: break
                    hash_algo.update(chunk)
            return hash_algo.hexdigest()
        except FileNotFoundError:
            logger.error(f"File not found during hash computation: {file_path}")
        except Exception as e:
            logger.error(f"Error computing hash for {file_path}: {e}")
        return None

    # --- Sending Logic ---

    async def request_send_item(self, peer_username, local_path):
        """
        Public method to initiate sending a file or folder to a connected peer.
        Validates peer connection and path, then delegates to specific handlers.
        """
        peer_ip = self.peer_manager.get_peer_ip(peer_username)
        websocket = self.peer_manager.get_websocket(peer_ip=peer_ip)

        # Validate peer connection state
        if not (peer_ip and websocket and websocket.open):
            await self._queue_ui_message(f"Error: Cannot send, peer '{peer_username}' not connected or connection invalid.")
            logger.warning(f"Send request failed: Peer '{peer_username}' ({peer_ip}) not connected or websocket invalid.")
            return

        local_path_abs = os.path.abspath(local_path)

        if os.path.isdir(local_path_abs):
            logger.info(f"Initiating folder send: '{local_path_abs}' to {peer_username} ({peer_ip})")
            # Start folder sending in a background task to avoid blocking UI/input handler
            asyncio.create_task(self._send_folder(peer_ip, websocket, local_path_abs))
        elif os.path.isfile(local_path_abs):
            logger.info(f"Initiating file send: '{local_path_abs}' to {peer_username} ({peer_ip})")
            # Start file sending in a background task
            asyncio.create_task(self._send_single_file(peer_ip, websocket, local_path_abs))
        else:
            await self._queue_ui_message(f"Error: Path not found or is not a valid file/directory: {local_path_abs}")
            logger.error(f"Send request failed: Path not found or invalid: {local_path_abs}")

    def _get_files_in_folder(self, folder_path):
        """Helper to recursively get files with relative paths (uses os specific separators initially)."""
        # Consider moving to utils.py
        file_list = []
        base_folder_name = os.path.basename(folder_path)
        if not os.path.isdir(folder_path):
            logger.error(f"Folder path does not exist or is not a directory: {folder_path}")
            return file_list, base_folder_name
        try:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    # Use os.path.relpath which should handle separators correctly for the OS
                    rel_path_os = os.path.relpath(full_path, folder_path)
                    # Convert to forward slashes for protocol consistency
                    rel_path_protocol = rel_path_os.replace(os.sep, '/')
                    file_list.append((full_path, rel_path_protocol))
        except Exception as e:
            logger.error(f"Error walking folder {folder_path}: {e}", exc_info=True)
        return file_list, base_folder_name


    async def _send_folder(self, peer_ip, websocket, folder_path):
        """Internal handler to orchestrate sending folder contents."""
        files_to_send, folder_name = self._get_files_in_folder(folder_path)
        peer_username = self.peer_manager.get_peer_username(peer_ip) or f"Peer_{peer_ip}"

        if not files_to_send:
            await self._queue_ui_message(f"No files found in folder: {folder_name}")
            return

        await self._queue_ui_message(f"Preparing to send folder '{folder_name}' ({len(files_to_send)} files) to {peer_username}...")

        # Send folder structure announcement message first
        folder_info_message = json.dumps({
            "type": "folder_transfer_init",
            "folder_name": folder_name, # Base name of the folder being sent
            "file_count": len(files_to_send)
        })
        try:
            await websocket.send(folder_info_message)
            logger.debug(f"Sent folder_transfer_init for '{folder_name}' to {peer_ip}")
        except Exception as e:
            logger.error(f"Failed to send folder init to {peer_ip}: {e}")
            await self._queue_ui_message(f"Error starting folder transfer to {peer_username}: {e}")
            # If init fails, assume connection is bad and remove peer
            await self.peer_manager.remove_peer(peer_ip, f"Failed folder init send: {e}")
            return

        # Send each file sequentially, waiting for ACK and completion/failure of each
        success_count = 0
        total_files = len(files_to_send)
        for i, (full_path, rel_path) in enumerate(files_to_send):
            if shutdown_event.is_set():
                await self._queue_ui_message("Folder transfer cancelled due to shutdown.")
                break
            # Check connection is still valid before sending each file
            current_ws = self.peer_manager.get_websocket(peer_ip=peer_ip)
            if not (current_ws and current_ws.open):
                await self._queue_ui_message(f"Peer {peer_username} disconnected during folder transfer. Aborting.")
                logger.warning(f"Peer {peer_ip} disconnected. Stopping folder transfer.")
                break # Exit loop

            # Construct the relative path as the receiver should see it (including base folder)
            remote_rel_path_with_folder = f"{folder_name}/{rel_path}"

            await self._queue_ui_message(f"Sending file {i+1}/{total_files}: '{rel_path}'...")
            # Use await here to ensure one file finishes (or fails) before starting the next
            # _send_single_file now handles the ACK wait internally and returns True/False on success/failure
            # The actual chunk sending runs in a background task initiated by _send_single_file
            file_init_success = await self._send_single_file(peer_ip, current_ws, full_path, remote_rel_path=remote_rel_path_with_folder)

            if file_init_success:
                # If initiation succeeded, we can conceptually count it, though chunks might still fail.
                # A more robust count would wait for the chunk sending task.
                # For simplicity now, assume init success means likely success.
                success_count += 1
                # Optional: Add a small delay between files if needed
                await asyncio.sleep(0.1)
            else:
                await self._queue_ui_message(f"Failed to initiate send for file '{rel_path}' in folder '{folder_name}'. Aborting folder transfer.")
                logger.warning(f"Aborting folder transfer to {peer_ip} due to failure sending '{rel_path}'.")
                # Should we try to continue? For now, abort on first file initiation failure.
                break
        else: # Only runs if the loop completed without a 'break'
             if not shutdown_event.is_set():
                  await self._queue_ui_message(f"Finished initiating transfers for {success_count}/{total_files} files in folder '{folder_name}'.")
                  logger.info(f"Completed folder transfer initiation loop for '{folder_name}' to {peer_ip}.")


    async def _send_single_file(self, peer_ip, websocket, local_path, remote_rel_path=None):
        """
        Internal handler to initiate sending a single file.
        Creates transfer object, sends init message, waits for ACK.
        If approved, starts the _send_chunks task.
        Returns: True if initiation and ACK were successful, False otherwise.
        """
        peer_username = self.peer_manager.get_peer_username(peer_ip) or f"Peer_{peer_ip}"
        if not os.path.exists(local_path):
            logger.error(f"File not found for sending: {local_path}")
            await self._queue_ui_message(f"Error: File not found - {local_path}")
            return False

        transfer_id = str(uuid.uuid4())
        try:
            file_size = os.path.getsize(local_path)
        except OSError as e:
             logger.error(f"Error getting size for file {local_path}: {e}")
             await self._queue_ui_message(f"Error accessing file {os.path.basename(local_path)}: {e}")
             return False

        # Use provided remote_rel_path (for folders) or just basename for single files
        display_name = remote_rel_path if remote_rel_path else os.path.basename(local_path)

        file_hash = await self._compute_hash(local_path)
        if file_hash is None:
            await self._queue_ui_message(f"Error computing hash for {display_name}. Aborting transfer.")
            return False

        # Create transfer object (initial state WAITING_ACK)
        transfer = FileTransfer(
            peer_ip=peer_ip, direction="send", transfer_id=transfer_id,
            total_size=file_size, local_path=local_path,
            remote_rel_path=display_name, expected_hash=file_hash
        )
        # Add to active transfers immediately for tracking
        self._active_transfers[transfer_id] = transfer

        # Prepare future to wait for ACK message
        ack_future = asyncio.Future()
        self._pending_send_acks[transfer_id] = ack_future

        # Prepare file_transfer_init message
        init_message = json.dumps({
            "type": "file_transfer_init",
            "transfer_id": transfer_id,
            "relative_path": display_name, # Send the path receiver should create relative to 'downloads'
            "filesize": file_size,
            "file_hash": file_hash
        })

        # --- Send Init and Wait for ACK ---
        try:
            await websocket.send(init_message)
            await self._queue_ui_message(f"Requesting to send '{display_name}' ({file_size} bytes) to {peer_username}. Waiting for approval...")
            logger.info(f"Sent file_transfer_init for {transfer_id} ('{display_name}') to {peer_ip}. Waiting for ACK.")

            # Wait for the ACK message (handle_file_ack will set the future)
            # Increased timeout to allow for user decision on receiver side
            approved = await asyncio.wait_for(ack_future, timeout=70.0) # e.g., 60s user + 10s network

            if approved:
                await self._queue_ui_message(f"Peer {peer_username} approved transfer for '{display_name}'. Starting...")
                logger.info(f"Transfer {transfer_id} approved by {peer_ip}. Starting chunk sending task.")
                transfer.update_state(TransferState.IN_PROGRESS)
                # Start sending chunks in a separate background task
                asyncio.create_task(self._send_chunks(transfer_id), name=f"SendChunks-{transfer_id[:8]}")
                return True # Transfer successfully initiated

            else:
                # Peer explicitly denied the transfer via ACK message
                await self._queue_ui_message(f"Peer {peer_username} denied transfer request for '{display_name}'.")
                logger.info(f"Transfer {transfer_id} denied by {peer_ip} via ACK.")
                transfer.update_state(TransferState.DENIED)
                # Cleanup of transfer object handled by progress task

        except asyncio.TimeoutError:
            logger.warning(f"Approval ACK timed out for transfer {transfer_id} to {peer_ip}.")
            await self._queue_ui_message(f"Peer {peer_username} did not respond to transfer request for '{display_name}'.")
            transfer.update_state(TransferState.DENIED) # Treat timeout as denial
        except websockets.exceptions.ConnectionClosed as e:
             logger.warning(f"Connection closed while waiting for ACK or sending init for {transfer_id} to {peer_ip}: {e}")
             await self._queue_ui_message(f"Connection lost during file request for '{display_name}' to {peer_username}.")
             transfer.update_state(TransferState.FAILED)
             # Connection is lost, ensure peer is removed by PeerManager
             # Avoid awaiting remove_peer here to prevent potential deadlocks if called from receive loop context
             asyncio.create_task(self.peer_manager.remove_peer(peer_ip, f"Conn closed during file init/ack: {e.code}"))
        except Exception as e:
            logger.exception(f"Error during file transfer initiation {transfer_id} to {peer_ip}: {e}")
            await self._queue_ui_message(f"Error starting transfer for '{display_name}': {e}")
            transfer.update_state(TransferState.FAILED)
            # Consider removing peer depending on error severity?

        # --- Cleanup if Initiation Failed ---
        # Ensure ACK future is removed if it still exists (e.g., exception before await)
        self._pending_send_acks.pop(transfer_id, None)
        # State is updated (FAILED or DENIED), progress task will handle removal from _active_transfers
        return False # Transfer failed to initiate properly

    async def _send_chunks(self, transfer_id):
        """Background task to read file chunks and send them over the websocket."""
        transfer = self._active_transfers.get(transfer_id)
        # Basic validation
        if not transfer:
             logger.error(f"_send_chunks task started for unknown transfer {transfer_id}. Exiting.")
             return
        if transfer.direction != "send":
             logger.error(f"_send_chunks task started for a 'receive' transfer {transfer_id}. Exiting.")
             transfer.update_state(TransferState.FAILED) # Mark as failed
             return
        if transfer.state != TransferState.IN_PROGRESS:
             logger.warning(f"_send_chunks task started for transfer {transfer_id} not in IN_PROGRESS state ({transfer.state.value}). Exiting.")
             # Don't mark as failed if paused, just exit task. If other state, might already be failed/denied.
             return

        peer_ip = transfer.peer_ip
        websocket = self.peer_manager.get_websocket(peer_ip=peer_ip)
        if not (websocket and websocket.open):
            logger.error(f"Cannot send chunks for {transfer_id}, peer {peer_ip} connection invalid/closed.")
            transfer.update_state(TransferState.FAILED)
            # Ensure peer is removed if connection unexpectedly closed
            asyncio.create_task(self.peer_manager.remove_peer(peer_ip, "Connection invalid at start of chunk send"))
            return

        logger.info(f"Starting chunk sending for {transfer_id} ('{transfer.remote_rel_path}') to {peer_ip}")
        try:
            async with aiofiles.open(transfer.local_path, "rb") as f:
                transfer.file_handle = f # Store handle on transfer object
                chunk_size = 1024 * 1024 # 1MB chunks

                while not shutdown_event.is_set():
                    # --- Pause/Resume Logic ---
                    async with transfer.condition:
                        while transfer.state == TransferState.PAUSED:
                            if shutdown_event.is_set(): # Check shutdown inside loop
                                 logger.info(f"Shutdown detected while transfer {transfer_id} was paused.")
                                 transfer.update_state(TransferState.FAILED)
                                 return # Exit task

                            logger.debug(f"Transfer {transfer_id} waiting (paused).")
                            try:
                                await asyncio.wait_for(transfer.condition.wait(), timeout=5.0) # Wait with timeout
                            except asyncio.TimeoutError:
                                 # Timeout just means we check shutdown_event again
                                 continue

                        # Re-check state after wait/timeout
                        if shutdown_event.is_set(): break # Exit outer loop
                        if transfer.state != TransferState.IN_PROGRESS:
                             # If state changed to FAILED/DENIED/COMPLETED while paused
                             logger.warning(f"Transfer {transfer_id} exited paused state into unexpected state {transfer.state.value}. Stopping chunk send.")
                             break # Exit outer loop

                    # --- Read Chunk ---
                    try:
                         chunk = await f.read(chunk_size)
                    except Exception as read_error:
                         logger.exception(f"Error reading file chunk for transfer {transfer_id}: {read_error}")
                         transfer.update_state(TransferState.FAILED)
                         break # Exit outer loop


                    if not chunk:
                        # End of file reached
                        logger.info(f"Finished reading file for transfer {transfer_id}. Total bytes read: {transfer.transferred_size}.")
                        # We assume completion based on reaching EOF. Receiver verifies size/hash.
                        # Sender marks itself as completed.
                        transfer.update_state(TransferState.COMPLETED)
                        break # Exit outer loop

                    # --- Send Chunk ---
                    chunk_message = json.dumps({
                        "type": "file_chunk",
                        "transfer_id": transfer_id,
                        # Send chunk data as hex string for JSON compatibility
                        "chunk": chunk.hex()
                    })

                    try:
                        # Check connection *before* sending each chunk
                        if not websocket.open:
                             logger.warning(f"Peer {peer_ip} disconnected during chunk send for {transfer_id}.")
                             transfer.update_state(TransferState.FAILED)
                             # Trigger peer removal, but don't await
                             asyncio.create_task(self.peer_manager.remove_peer(peer_ip, "Disconnected during chunk send"))
                             break # Exit outer loop

                        # Perform the send operation
                        await websocket.send(chunk_message)
                        transfer.transferred_size += len(chunk)
                        # logger.debug(f"Sent chunk {transfer.transferred_size}/{transfer.total_size} for {transfer_id}")

                    except websockets.exceptions.ConnectionClosed as e:
                         logger.warning(f"Connection to {peer_ip} closed while sending chunk for {transfer_id}: {e}")
                         transfer.update_state(TransferState.FAILED)
                         # Trigger peer removal, but don't await
                         asyncio.create_task(self.peer_manager.remove_peer(peer_ip, f"Conn closed sending chunk: {e.code}"))
                         break # Exit outer loop
                    except Exception as send_err:
                         logger.exception(f"Error sending chunk for transfer {transfer_id} to {peer_ip}: {send_err}")
                         transfer.update_state(TransferState.FAILED)
                         # Consider removing peer depending on error? Maybe not for transient errors.
                         break # Exit outer loop

                    # Yield control briefly to allow other tasks to run
                    await asyncio.sleep(0.001) # Very short sleep to yield

        except FileNotFoundError:
             logger.error(f"File {transfer.local_path} vanished during transfer {transfer_id}!")
             transfer.update_state(TransferState.FAILED)
        except asyncio.CancelledError:
             logger.info(f"Chunk sending task for {transfer_id} cancelled.")
             transfer.update_state(TransferState.FAILED) # Mark as failed if cancelled externally
        except Exception as e:
            logger.exception(f"Unexpected error during chunk sending task for {transfer_id}: {e}")
            if transfer and transfer.state != TransferState.FAILED:
                 transfer.update_state(TransferState.FAILED)
        finally:
            logger.debug(f"Chunk sending task for {transfer_id} ending with state: {transfer.state.value if transfer else 'N/A'}")
            # Ensure file handle is closed if transfer object still exists
            if transfer:
                await transfer.close_handle()
            # The progress update task handles final removal based on state.


    # --- Receiving Logic ---

    async def handle_folder_init(self, peer_ip, folder_name, file_count):
        """Handles the announcement of an incoming folder transfer."""
        peer_username = self.peer_manager.get_peer_username(peer_ip) or f"Peer_{peer_ip}"
        if folder_name and isinstance(file_count, int):
            await self._queue_ui_message(f"Receiving folder '{folder_name}' ({file_count} files) from {peer_username}...")
            logger.info(f"Received folder init for '{folder_name}' ({file_count} files) from {peer_ip}")
            # Optional: Create the base directory in 'downloads' early
            # try:
            #     download_base = os.path.join("downloads", folder_name)
            #     os.makedirs(download_base, exist_ok=True)
            # except OSError as e:
            #     logger.error(f"Failed to create base directory for incoming folder '{folder_name}': {e}")
            #     # How to handle this? Maybe subsequent file creations will fail.
        else:
            logger.warning(f"Received invalid folder_transfer_init from {peer_ip}: Name='{folder_name}', Count='{file_count}'")

    async def handle_file_init_request(self, peer_ip, transfer_id, relative_path, file_size, file_hash):
        """
        Handles an incoming file transfer request ('file_transfer_init' message).
        Validates request, asks UI for approval, sends ACK, and prepares for chunks if approved.
        """
        peer_username = self.peer_manager.get_peer_username(peer_ip) or f"Peer_{peer_ip}"
        logger.info(f"Received file transfer request {transfer_id} ('{relative_path}', {file_size} bytes) from {peer_username} ({peer_ip})")

        # --- Validation ---
        if not all([transfer_id, relative_path, isinstance(file_size, int), file_hash]):
             logger.warning(f"Invalid file_transfer_init from {peer_ip}: Missing/invalid data.")
             # Optionally send an immediate denial ACK back? Needs websocket access.
             # await self._send_ack(peer_ip, transfer_id, False) # Helper needed
             return
        if transfer_id in self._active_transfers or transfer_id in self._pending_receive_approvals:
             logger.warning(f"Duplicate file transfer init received for ID {transfer_id} from {peer_ip}. Ignoring.")
             # Optionally send denial ACK?
             # await self._send_ack(peer_ip, transfer_id, False)
             return
        if file_size < 0:
             logger.warning(f"Received file transfer init with invalid size {file_size} for {transfer_id} from {peer_ip}. Ignoring.")
             # await self._send_ack(peer_ip, transfer_id, False)
             return

        # --- Prepare Local Path ---
        # Construct local path safely, preventing directory traversal
        # Split the relative path and join it under 'downloads' directory
        path_parts = [part for part in relative_path.split('/') if part and part != '..']
        if not path_parts:
             logger.warning(f"Received file transfer init with invalid relative path '{relative_path}' for {transfer_id}. Ignoring.")
             # await self._send_ack(peer_ip, transfer_id, False)
             return
        local_intended_path = os.path.join("downloads", *path_parts)
        local_intended_path_abs = os.path.abspath(local_intended_path)

        # Double-check the path is still within 'downloads' after joining/abs
        downloads_abs = os.path.abspath("downloads")
        if not local_intended_path_abs.startswith(downloads_abs):
             logger.critical(f"Potential directory traversal attempt in file transfer path: '{relative_path}' -> '{local_intended_path_abs}'. Denying.")
             await self._queue_ui_message(f"[SECURITY] Denied unsafe file path request: '{relative_path}'")
             await self._send_ack(peer_ip, transfer_id, False) # Send denial explicitly
             return

        # Ensure target directory exists
        try:
             os.makedirs(os.path.dirname(local_intended_path_abs), exist_ok=True)
        except OSError as e:
             logger.error(f"Failed to create directory for receiving file '{local_intended_path_abs}': {e}")
             await self._queue_ui_message(f"[ERROR] Cannot create directory for download: {e}")
             await self._send_ack(peer_ip, transfer_id, False) # Deny if dir creation fails
             return

        # --- Create Transfer Object (State PENDING_APPROVAL) ---
        transfer = FileTransfer(
            peer_ip=peer_ip, direction="receive", transfer_id=transfer_id,
            total_size=file_size, local_path=local_intended_path_abs, # Use absolute path internally
            remote_rel_path=relative_path, expected_hash=file_hash
        )
        self._active_transfers[transfer_id] = transfer

        # --- Request UI Approval ---
        approval_future = asyncio.Future()
        self._pending_receive_approvals[transfer_id] = approval_future
        approved = False
        ack_sent = False

        try:
             # Ask UIManager to display prompt and link to the future
             # UIManager handles the display and setting the future result via 'yes'/'no'
             await self.ui_manager.request_file_approval(
                 transfer_id, peer_username, relative_path, file_size
             )
             logger.debug(f"Waiting for UI approval future for transfer {transfer_id}")
             # Wait for the UI Manager (via user input) to set the future result
             approved = await asyncio.wait_for(approval_future, timeout=70.0) # User decision timeout

        except asyncio.TimeoutError:
            logger.info(f"File transfer approval {transfer_id} from {peer_username} timed out.")
            await self._queue_ui_message(f"Approval for '{relative_path}' from {peer_username} timed out.")
            transfer.update_state(TransferState.DENIED) # Mark as denied on timeout
        except asyncio.CancelledError:
             logger.info(f"File approval task cancelled for {transfer_id}")
             transfer.update_state(TransferState.FAILED) # Mark failed if approval cancelled
             # Re-raise cancellation if needed by caller context
             # raise
        except Exception as e:
             logger.exception(f"Error during file approval process for {transfer_id}: {e}")
             transfer.update_state(TransferState.FAILED)
        finally:
            # Clean up pending approval future regardless of outcome
             self._pending_receive_approvals.pop(transfer_id, None)
             # UIManager should clear its own context tracking the prompt


        # --- Send ACK Back to Sender ---
        try:
             ack_sent = await self._send_ack(peer_ip, transfer_id, approved)
        except Exception as e:
             logger.error(f"Error occurred trying to send ACK for {transfer_id}: {e}")
             # If ACK sending fails, the sender will likely timeout.
             # Treat receiver state as failed if approved but ACK failed.
             if approved:
                 transfer.update_state(TransferState.FAILED)
                 await self._queue_ui_message(f"Approved '{relative_path}' but failed to notify sender.")
             # If denied, state is already DENIED (or FAILED from timeout)


        # --- Prepare for Receiving Chunks (if approved and ACK sent) ---
        if approved and ack_sent:
            await self._queue_ui_message(f"Approved receiving '{relative_path}'. Preparing download...")
            try:
                # Open file handle (binary write) and update state
                transfer.file_handle = await aiofiles.open(transfer.local_path, "wb")
                # Reset hash algo for receiving
                transfer.hash_algo = hashlib.sha256() if transfer.expected_hash else None
                transfer.transferred_size = 0
                transfer.update_state(TransferState.IN_PROGRESS) # Ready for chunks
                logger.info(f"Transfer {transfer_id}: Approved and ready for chunks at {transfer.local_path}")

            except Exception as e:
                 logger.exception(f"Error opening file {transfer.local_path} for receiving chunks: {e}")
                 await self._queue_ui_message(f"[ERROR] Could not open file for download: {e}")
                 transfer.update_state(TransferState.FAILED)
                 await transfer.close_handle() # Ensure handle is closed if opened partially
                 # TODO: Optionally try to send an error message back to sender? Complex.
        elif approved and not ack_sent:
             # Already handled logging/state update in ACK sending block
             pass
        else: # Denied by user, timed out, or setup error before ACK
             if transfer.state not in (TransferState.FAILED, TransferState.DENIED):
                 # Ensure state is correctly set if not already FAILED/DENIED
                 transfer.update_state(TransferState.DENIED)
             logger.info(f"Transfer {transfer_id} from {peer_username} denied or failed setup.")
             if not approved and ack_sent: # Check if denial was sent successfully
                  await self._queue_ui_message(f"Denied file transfer '{relative_path}' from {peer_username}.")
             # Progress task will handle cleanup of denied/failed transfer object


    async def _send_ack(self, peer_ip, transfer_id, approved):
         """Helper to send the file_transfer_ack message."""
         websocket = self.peer_manager.get_websocket(peer_ip=peer_ip)
         if websocket and websocket.open:
             ack_message = json.dumps({
                 "type": "file_transfer_ack",
                 "transfer_id": transfer_id,
                 "approved": bool(approved) # Ensure boolean
             })
             try:
                 await websocket.send(ack_message)
                 logger.debug(f"Sent file ACK for {transfer_id} to {peer_ip}: Approved={approved}")
                 return True
             except websockets.exceptions.ConnectionClosed as e:
                  logger.warning(f"Connection closed while sending file ACK for {transfer_id} to {peer_ip}: {e}")
                  # Trigger peer removal as connection is dead
                  asyncio.create_task(self.peer_manager.remove_peer(peer_ip, f"Conn closed sending ACK: {e.code}"))
             except Exception as e:
                  logger.error(f"Error sending file ACK for {transfer_id} to {peer_ip}: {e}")
         else:
             logger.warning(f"Cannot send file ACK for {transfer_id}, peer {peer_ip} disconnected or websocket invalid.")
             # If peer disconnected, ensure they are removed
             if self.peer_manager.is_connected(peer_ip=peer_ip): # Check if manager still thinks they are connected
                  asyncio.create_task(self.peer_manager.remove_peer(peer_ip, "Websocket invalid sending ACK"))
         return False


    def handle_file_ack(self, peer_ip, transfer_id, approved):
        """
        Handles the 'file_transfer_ack' message received by the ORIGINAL SENDER.
        Resolves the corresponding future in _pending_send_acks.
        """
        ack_future = self._pending_send_acks.pop(transfer_id, None)
        if ack_future and not ack_future.done():
            logger.debug(f"Received file ACK for transfer {transfer_id} from {peer_ip}: Approved={approved}")
            ack_future.set_result(bool(approved)) # Set future result (True/False)
        elif ack_future:
             logger.warning(f"Received duplicate/late file ACK for already resolved transfer {transfer_id} from {peer_ip}")
        else:
             # This can happen if the sender already timed out waiting for the ACK
             logger.warning(f"Received unexpected file ACK (no pending future) for transfer {transfer_id} from {peer_ip}. Might have timed out.")
             # Check if the transfer still exists and its state
             transfer = self._active_transfers.get(transfer_id)
             if transfer and transfer.state == TransferState.DENIED: # DENIED state often means sender timed out
                  logger.debug(f"Ignoring late ACK for transfer {transfer_id} which already timed out/failed.")
             elif transfer:
                  logger.warning(f"Late ACK for transfer {transfer_id} in state {transfer.state.value}. Ignoring.")


    async def handle_file_chunk(self, peer_ip, transfer_id, chunk_hex):
        """Handles a received 'file_chunk' message."""
        transfer = self._active_transfers.get(transfer_id)

        # --- Validation ---
        if not transfer:
            # Can happen if transfer completed/failed just before chunk arrived
            logger.debug(f"Received chunk for unknown/completed transfer {transfer_id} from {peer_ip}. Ignoring.")
            return
        if transfer.direction != "receive":
            logger.warning(f"Received file chunk message for a 'send' transfer {transfer_id}. Protocol violation?")
            # Mark failed? Or just ignore? Ignore for robustness.
            return
        if transfer.peer_ip != peer_ip:
             logger.warning(f"Received chunk for transfer {transfer_id} from wrong peer {peer_ip} (expected {transfer.peer_ip}). Ignoring.")
             return
        if transfer.state != TransferState.IN_PROGRESS:
             if transfer.state == TransferState.PAUSED:
                  logger.debug(f"Ignoring chunk for paused transfer {transfer_id}")
             else:
                  # Ignore chunks if completed, failed, denied, etc. Sender might send extra.
                  logger.debug(f"Ignoring chunk for transfer {transfer_id} in non-receiving state {transfer.state.value}.")
             return
        if not transfer.file_handle or transfer.file_handle.closed:
             logger.error(f"Transfer {transfer_id}: File handle closed or missing while receiving chunk. Marking failed.")
             transfer.update_state(TransferState.FAILED)
             # Ensure progress task cleans up
             return
        if not chunk_hex:
             logger.warning(f"Received empty file chunk data for {transfer_id} from {peer_ip}. Assuming error, marking failed.")
             transfer.update_state(TransferState.FAILED)
             await transfer.close_handle()
             return

        # --- Process Chunk ---
        try:
            # Decode hex data
            chunk = bytes.fromhex(chunk_hex)
            chunk_len = len(chunk)

            # Check if receiving this chunk would exceed expected size
            if transfer.transferred_size + chunk_len > transfer.total_size:
                 logger.warning(f"Transfer {transfer_id}: Receiving chunk would exceed expected size ({transfer.transferred_size + chunk_len} > {transfer.total_size}). Truncating/Failing.")
                 # Option 1: Truncate the chunk
                 # chunk = chunk[:transfer.total_size - transfer.transferred_size]
                 # chunk_len = len(chunk)
                 # Option 2: Mark as failed (safer?)
                 transfer.update_state(TransferState.FAILED)
                 await transfer.close_handle()
                 await self._queue_ui_message(f"❌ File '{transfer.remote_rel_path}' failed: Received too much data.")
                 try: os.remove(transfer.local_path) # Attempt cleanup
                 except OSError: pass
                 return

            # Write chunk to file
            await transfer.file_handle.write(chunk)
            transfer.transferred_size += chunk_len

            # Update hash if applicable
            if transfer.hash_algo:
                transfer.hash_algo.update(chunk)

            # --- Check Completion ---
            if transfer.transferred_size == transfer.total_size:
                logger.info(f"Transfer {transfer_id}: Received expected size ({transfer.total_size} bytes). Finalizing...")
                await transfer.close_handle() # Close file handle *before* hash verification

                # Verify hash if provided
                final_state = TransferState.FAILED # Assume failed unless verified
                if transfer.expected_hash:
                    if not transfer.hash_algo: # Should not happen if hash was expected
                         logger.error(f"Transfer {transfer_id}: Hash expected but hash object not available!")
                         await self._queue_ui_message(f"❌ File '{transfer.remote_rel_path}' failed: Hash calculation error.")
                    else:
                        calculated_hash = transfer.hash_algo.hexdigest()
                        if calculated_hash == transfer.expected_hash:
                            final_state = TransferState.COMPLETED
                            await self._queue_ui_message(f"✅ File '{transfer.remote_rel_path}' received successfully and verified.")
                            logger.info(f"Transfer {transfer_id}: Hash verification successful.")
                        else:
                            # Hash mismatch
                            await self._queue_ui_message(f"❌ File '{transfer.remote_rel_path}' failed integrity check! Deleted.")
                            logger.warning(f"Transfer {transfer_id}: Hash mismatch! Expected {transfer.expected_hash}, got {calculated_hash}. Deleting file.")
                            try:
                                 os.remove(transfer.local_path)
                                 logger.debug(f"Deleted corrupted file: {transfer.local_path}")
                            except OSError as e:
                                 logger.error(f"Failed to delete corrupted file {transfer.local_path}: {e}")
                else:
                    # No hash verification required
                    final_state = TransferState.COMPLETED
                    await self._queue_ui_message(f"✅ File '{transfer.remote_rel_path}' received successfully (no hash provided).")
                    logger.info(f"Transfer {transfer_id}: Completed (no hash verification).")

                transfer.update_state(final_state)

            elif transfer.transferred_size > transfer.total_size:
                 # This case should ideally be caught by the check before writing, but as safety net
                 logger.error(f"Transfer {transfer_id} wrote more data ({transfer.transferred_size}) than expected ({transfer.total_size}). Logic error?")
                 transfer.update_state(TransferState.FAILED)
                 await transfer.close_handle()
                 await self._queue_ui_message(f"❌ File '{transfer.remote_rel_path}' failed: Wrote too much data.")
                 try: os.remove(transfer.local_path)
                 except OSError: pass


        except ValueError as e: # bytes.fromhex error
             logger.error(f"Transfer {transfer_id}: Invalid hex data in chunk from {peer_ip}: {e}")
             transfer.update_state(TransferState.FAILED)
             await transfer.close_handle()
             await self._queue_ui_message(f"❌ File '{transfer.remote_rel_path}' failed: Received corrupt data.")
             try: os.remove(transfer.local_path)
             except OSError: pass
        except asyncio.CancelledError:
             logger.info(f"Chunk handling cancelled for {transfer_id}")
             # Don't change state here, cancellation implies external stop
             # Ensure handle is closed though
             await transfer.close_handle()
             raise # Re-raise cancellation
        except Exception as e:
            logger.exception(f"Transfer {transfer_id}: Error writing file chunk from {peer_ip}: {e}")
            transfer.update_state(TransferState.FAILED)
            await transfer.close_handle()
            await self._queue_ui_message(f"❌ File '{transfer.remote_rel_path}' failed: Error writing data.")
            try: os.remove(transfer.local_path)
            except OSError: pass


    # --- Control and Cleanup ---

    async def pause_transfer(self, transfer_id):
        """Pause an active transfer."""
        transfer = self._active_transfers.get(transfer_id)
        if transfer:
             if await transfer.pause(): # pause method logs success/failure reason
                 # await self._queue_ui_message(f"Transfer {transfer_id} pause requested.") # Optional UI msg
                 pass
             else:
                 await self._queue_ui_message(f"Transfer {transfer_id} cannot be paused in state {transfer.state.value}.")
        else:
             await self._queue_ui_message(f"No active transfer found with ID: {transfer_id}")

    async def resume_transfer(self, transfer_id):
        """Resume a paused transfer."""
        transfer = self._active_transfers.get(transfer_id)
        if transfer:
             if await transfer.resume(): # resume method logs success/failure reason
                 # await self._queue_ui_message(f"Transfer {transfer_id} resume requested.") # Optional UI msg
                 pass
             else:
                 await self._queue_ui_message(f"Transfer {transfer_id} cannot be resumed in state {transfer.state.value}.")
        else:
             await self._queue_ui_message(f"No active transfer found with ID: {transfer_id}")

    async def cleanup_peer_transfers(self, peer_ip):
        """Mark transfers involving a disconnected peer as failed and clean up resources."""
        logger.info(f"Cleaning up transfers for disconnected peer {peer_ip}")
        tasks = []
        for tid, transfer in list(self._active_transfers.items()):
             if transfer.peer_ip == peer_ip:
                  if transfer.state not in (TransferState.COMPLETED, TransferState.FAILED, TransferState.DENIED):
                       logger.warning(f"Marking active transfer {tid} ({transfer.state.value}) as failed due to peer {peer_ip} disconnection.")
                       transfer.update_state(TransferState.FAILED)
                       # Schedule handle closing concurrently
                       tasks.append(asyncio.create_task(transfer.close_handle()))
                  # Also cancel/remove related pending futures immediately
                  future_ack = self._pending_send_acks.pop(tid, None)
                  if future_ack and not future_ack.done(): future_ack.cancel()
                  future_recv = self._pending_receive_approvals.pop(tid, None)
                  if future_recv and not future_recv.done(): future_recv.cancel()
        # Wait for any scheduled handle closures
        if tasks:
             await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug(f"Finished cleanup tasks for peer {peer_ip} transfers.")


    def get_active_transfers_info(self):
         """Return a list of strings describing active transfers for the UI."""
         if not self._active_transfers:
             return ["No active file transfers."]

         output = ["\n--- Active Transfers ---"]
         # Sort by transfer ID or other criteria? For now, dict order.
         for tid, t in self._active_transfers.items():
             direction = "Sending" if t.direction == "send" else "Receiving"
             # Attempt to get username, fallback to IP
             peer_uname = self.peer_manager.get_peer_username(t.peer_ip) or t.peer_ip
             path_display = t.remote_rel_path # Use the relative path stored
             try: # Calculate progress safely
                 progress = (t.transferred_size / t.total_size * 100) if t.total_size > 0 else (100 if t.state == TransferState.COMPLETED else 0)
             except ZeroDivisionError:
                 progress = 0 # Handle case where total_size might be 0 unexpectedly

             output.append(f"- ID: {tid}")
             output.append(f"    {'To' if direction=='Sending' else 'From'}: {peer_uname}")
             output.append(f"    Item: '{path_display}'")
             output.append(f"    State: {t.state.value} ({progress:.1f}%)")
             # Display human-readable sizes? (Optional)
             output.append(f"    Size: {t.transferred_size} / {t.total_size} bytes")
         return output

    async def run_progress_updates(self, interval=2):
        """Task to periodically log progress and remove finished transfers from the active list."""
        logger.info("Transfer progress update task started.")
        while not shutdown_event.is_set():
            next_run_time = asyncio.get_event_loop().time() + interval
            try:
                items_to_remove = []
                # Iterate over a copy of items in case cleanup modifies the dict
                for transfer_id, transfer in list(self._active_transfers.items()):
                    # Log progress for IN_PROGRESS transfers occasionally
                    if transfer.state == TransferState.IN_PROGRESS and transfer.total_size > 0:
                        # Simple logging for now, could add throttling
                        # progress = (transfer.transferred_size / transfer.total_size) * 100
                        # logger.debug(f"Transfer {transfer_id} progress: {progress:.1f}%")
                        pass # Reduce log spam, maybe log every N seconds or % change

                    # Check for final states to schedule removal
                    if transfer.state in (TransferState.COMPLETED, TransferState.FAILED, TransferState.DENIED):
                        logger.debug(f"Scheduling removal for transfer {transfer_id} in state {transfer.state.value}")
                        items_to_remove.append(transfer_id)
                        # Ensure file handle is closed (should be done by state change, but double-check)
                        if transfer.file_handle and not transfer.file_handle.closed:
                             logger.warning(f"Found open file handle for finalized transfer {transfer_id}. Closing now.")
                             await transfer.close_handle()

                # Remove items outside the loop iteration
                if items_to_remove:
                    logger.debug(f"Removing {len(items_to_remove)} finished transfers.")
                    for transfer_id in items_to_remove:
                        removed_transfer = self._active_transfers.pop(transfer_id, None)
                        if removed_transfer:
                            logger.info(f"Removed transfer {transfer_id} (State: {removed_transfer.state.value}) from active list.")
                            # Ensure related futures are definitely cleaned up
                            future_ack = self._pending_send_acks.pop(transfer_id, None)
                            if future_ack: logger.debug(f"Cleaned up send ACK future for {transfer_id}")
                            future_recv = self._pending_receive_approvals.pop(transfer_id, None)
                            if future_recv: logger.debug(f"Cleaned up receive approval future for {transfer_id}")
                        else:
                             logger.warning(f"Attempted to remove transfer {transfer_id}, but it was already gone.")

                # Wait until the next scheduled run time
                await asyncio.sleep(max(0, next_run_time - asyncio.get_event_loop().time()))

            except asyncio.CancelledError:
                logger.info("Transfer progress update task cancelled.")
                break
            except Exception as e:
                logger.exception(f"Error in transfer progress update task loop: {e}")
                # Avoid tight loop on error, wait longer before retrying
                await asyncio.sleep(interval * 2)
        logger.info("Transfer progress update task stopped.")

        # --- Final Cleanup on Shutdown ---
        logger.info("Cleaning up remaining file transfers on shutdown...")
        cleanup_tasks = []
        for tid, transfer in list(self._active_transfers.items()):
             if transfer.state not in (TransferState.COMPLETED, TransferState.FAILED, TransferState.DENIED):
                 logger.warning(f"Marking remaining active transfer {tid} ({transfer.state.value}) as failed during shutdown.")
                 transfer.update_state(TransferState.FAILED)
             # Ensure all handles are closed
             cleanup_tasks.append(asyncio.create_task(transfer.close_handle()))

        if cleanup_tasks:
             await asyncio.gather(*cleanup_tasks, return_exceptions=True) # Wait for handles to close

        self._active_transfers.clear()
        self._pending_receive_approvals.clear()
        self._pending_send_acks.clear()
        logger.info("Transfer manager final cleanup complete.")