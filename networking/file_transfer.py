import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
from enum import Enum
from networking.shared_state import (
    active_transfers,
    shutdown_event,
    pending_file_send_acks, # Use this for sender waiting for ACK
    connections # Import connections to check if peer is still connected
)

class TransferState(Enum):
    PENDING_APPROVAL = "pending_approval" # Added state for receiver
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied" # Added state for receiver

class FileTransfer:
    def __init__(self, file_path, peer_ip, direction="send", total_size=0, transfer_id=None):
        self.file_path = file_path # Local path (send) or intended path (receive)
        self.peer_ip = peer_ip
        self.direction = direction
        self.transfer_id = transfer_id if transfer_id else str(uuid.uuid4())
        self.total_size = total_size if total_size else (os.path.getsize(file_path) if os.path.exists(file_path) else 0)
        self.transferred_size = 0
        self.file_handle = None
        # Initial state depends on direction
        self.state = TransferState.IN_PROGRESS if direction == "send" else TransferState.PENDING_APPROVAL
        self.hash_algo = hashlib.sha256()
        self.expected_hash = None
        self.condition = asyncio.Condition()
        self.relative_path = None # Store relative path for receiving folders

    async def pause(self):
        """Pause the file transfer."""
        async with self.condition:
            if self.state == TransferState.IN_PROGRESS:
                self.state = TransferState.PAUSED
                logging.info(f"Transfer {self.transfer_id} paused.")

    async def resume(self):
        """Resume the file transfer."""
        async with self.condition:
            if self.state == TransferState.PAUSED:
                self.state = TransferState.IN_PROGRESS
                self.condition.notify_all()
                logging.info(f"Transfer {self.transfer_id} resumed.")

    # Helper to update state and log removal
    def update_state(self, new_state):
        self.state = new_state
        if new_state in (TransferState.COMPLETED, TransferState.FAILED, TransferState.DENIED):
             # Ensure cleanup happens quickly after final state is reached
            if self.transfer_id in active_transfers:
                logging.debug(f"Marking transfer {self.transfer_id} for removal (State: {new_state.value})")
            # The update_transfer_progress task will handle the actual removal


async def compute_hash(file_path):
    """Compute the SHA-256 hash of a file in chunks asynchronously."""
    hash_algo = hashlib.sha256()
    try:
        async with aiofiles.open(file_path, "rb") as f:
            while True:
                chunk = await f.read(1024 * 1024)  # Read 1MB chunks
                if not chunk:
                    break
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found during hash computation: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None


def get_files_in_folder(folder_path):
    """Recursively collect all files in a folder with their relative paths."""
    file_list = []
    if not os.path.isdir(folder_path):
        logging.error(f"Folder path does not exist or is not a directory: {folder_path}")
        return file_list
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            # Ensure relative path uses forward slashes for cross-platform compatibility
            rel_path = os.path.relpath(full_path, folder_path).replace(os.sep, '/')
            file_list.append((full_path, rel_path))
    return file_list

async def send_folder(folder_path, target_peer_ip, target_websocket):
    """Send all files in a folder to a specific peer, preserving structure."""
    from networking.shared_state import message_queue # Local import
    file_list = get_files_in_folder(folder_path)
    if not file_list:
        await message_queue.put(f"No files found in folder: {folder_path}")
        return

    folder_name = os.path.basename(folder_path)
    await message_queue.put(f"Preparing to send folder '{folder_name}' ({len(file_list)} files)...")

    # Send a folder structure message first (optional, but good practice)
    folder_info_message = json.dumps({
        "type": "folder_transfer_init",
        "folder_name": folder_name,
        "file_count": len(file_list)
    })
    try:
        await target_websocket.send(folder_info_message)
    except Exception as e:
        logging.error(f"Failed to send folder init to {target_peer_ip}: {e}")
        await message_queue.put(f"Error starting folder transfer to {target_peer_ip}: {e}")
        return


    # Send each file, ensuring the peer connection is still valid
    for full_path, rel_path in file_list:
        if shutdown_event.is_set():
            await message_queue.put("Folder transfer cancelled due to shutdown.")
            break
        if target_peer_ip not in connections or not connections[target_peer_ip].open:
            await message_queue.put(f"Peer {target_peer_ip} disconnected during folder transfer. Aborting.")
            logging.warning(f"Peer {target_peer_ip} disconnected. Stopping folder transfer.")
            break

        # Pass the specific websocket connection for this file
        await send_file(full_path, {target_peer_ip: target_websocket}, relative_path=rel_path)
        # Add a small delay to prevent overwhelming the network/receiver buffer
        await asyncio.sleep(0.1)

    if not shutdown_event.is_set() and target_peer_ip in connections:
         await message_queue.put(f"Finished sending files for folder '{folder_name}'.")


async def send_file(file_path, peers, relative_path=None):
    """Send a file to specified peers concurrently, waiting for approval."""
    from networking.shared_state import message_queue # Local import

    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        await message_queue.put(f"Error: File not found - {file_path}")
        return

    transfer_id = str(uuid.uuid4())
    file_size = os.path.getsize(file_path)
    display_name = relative_path if relative_path else os.path.basename(file_path)

    file_hash = await compute_hash(file_path)
    if file_hash is None:
        await message_queue.put(f"Error computing hash for {display_name}. Aborting transfer.")
        return

    # Initialize transfer object immediately for tracking purposes
    # Assume only one peer for simplicity in this version's command structure
    peer_ip = list(peers.keys())[0]
    transfer = FileTransfer(file_path, peer_ip, direction="send", total_size=file_size, transfer_id=transfer_id)
    transfer.expected_hash = file_hash
    transfer.relative_path = display_name # Store for logging/display
    active_transfers[transfer_id] = transfer
    logging.info(f"Initiating transfer {transfer_id} ({display_name}) to {peer_ip}. Waiting for approval.")
    await message_queue.put(f"Requesting to send '{display_name}' ({file_size} bytes) to {peer_ip}. Waiting for approval...")

    # Prepare init message
    init_message = json.dumps({
        "type": "file_transfer_init",
        "transfer_id": transfer_id,
        "relative_path": display_name, # Send the path to be used by receiver
        "filesize": file_size,
        "file_hash": file_hash
    })

    # Prepare futures to wait for ACKs
    ack_futures = {}
    pending_file_send_acks[transfer_id] = ack_futures

    # Send init message to all target peers
    disconnected_peers = []
    for p_ip, websocket in peers.items():
        try:
            await websocket.send(init_message)
            ack_futures[p_ip] = asyncio.Future() # Create future to wait for ACK
        except Exception as e:
            logging.error(f"Failed to send file init to {p_ip}: {e}")
            disconnected_peers.append(p_ip)

    # Remove peers that failed initial send
    for p_ip in disconnected_peers:
        del peers[p_ip]
        if p_ip in ack_futures:
             del ack_futures[p_ip]

    if not peers:
        logging.warning(f"Transfer {transfer_id}: No peers left to send to after init.")
        transfer.update_state(TransferState.FAILED)
        if transfer_id in pending_file_send_acks: del pending_file_send_acks[transfer_id]
        # Removal from active_transfers handled by update_transfer_progress
        return

    # Wait for ACKs (approvals/denials) from peers
    try:
        # Wait for all futures associated with this transfer_id
        await asyncio.wait_for(
            asyncio.gather(*ack_futures.values()),
            timeout=60.0 # Increased timeout for user response
        )
    except asyncio.TimeoutError:
        logging.warning(f"Transfer {transfer_id}: Approval timed out for some peers.")
        # Peers whose futures didn't complete are implicitly denied or timed out
        for p_ip, future in ack_futures.items():
            if not future.done():
                future.set_exception(asyncio.TimeoutError()) # Mark as timed out

    # Filter peers based on approval status in the future result
    approved_peers = {}
    denied_count = 0
    for p_ip, future in ack_futures.items():
        if future.done() and not future.cancelled():
            try:
                approved = future.result() # Result should be True (approved) or False (denied)
                if approved:
                    approved_peers[p_ip] = peers[p_ip]
                    logging.info(f"Transfer {transfer_id}: Peer {p_ip} approved.")
                    await message_queue.put(f"Peer {p_ip} approved transfer for '{display_name}'.")
                else:
                    denied_count += 1
                    logging.info(f"Transfer {transfer_id}: Peer {p_ip} denied.")
                    await message_queue.put(f"Peer {p_ip} denied transfer for '{display_name}'.")
            except asyncio.TimeoutError:
                 logging.warning(f"Transfer {transfer_id}: Peer {p_ip} timed out.")
                 await message_queue.put(f"Peer {p_ip} did not respond to transfer request for '{display_name}'.")
                 denied_count +=1
            except Exception as e:
                 logging.error(f"Transfer {transfer_id}: Error getting approval result from {p_ip}: {e}")
                 denied_count += 1
        else:
             # Future not done (implies timeout if gather finished) or cancelled
             logging.warning(f"Transfer {transfer_id}: No valid response from {p_ip}.")
             denied_count += 1


    # Clean up ack futures
    if transfer_id in pending_file_send_acks:
        del pending_file_send_acks[transfer_id]

    if not approved_peers:
        logging.info(f"Transfer {transfer_id} denied or failed for all peers.")
        transfer.update_state(TransferState.FAILED if denied_count == 0 else TransferState.DENIED)
        # Removal from active_transfers handled by update_transfer_progress
        return

    # Proceed with sending chunks ONLY to approved peers
    peers_to_send_to = approved_peers
    await message_queue.put(f"Starting transfer of '{display_name}' to approved peers...")

    try:
        async with aiofiles.open(file_path, "rb") as f:
            transfer.file_handle = f
            chunk_size = 1024 * 1024  # 1MB chunks
            while not shutdown_event.is_set() and transfer.state != TransferState.FAILED:
                # --- Pause/Resume Logic ---
                async with transfer.condition:
                    while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                        logging.debug(f"Transfer {transfer_id} waiting (paused).")
                        await transfer.condition.wait()

                    if shutdown_event.is_set():
                        logging.info(f"Transfer {transfer_id} cancelled due to shutdown.")
                        transfer.update_state(TransferState.FAILED)
                        break
                    if transfer.state == TransferState.FAILED: # Check if failed during pause
                         break
                    # Ensure state is IN_PROGRESS before reading
                    transfer.state = TransferState.IN_PROGRESS

                # --- Read Chunk ---
                try:
                    chunk = await f.read(chunk_size)
                except Exception as read_error:
                    logging.exception(f"Transfer {transfer_id}: Error reading file chunk: {read_error}")
                    transfer.update_state(TransferState.FAILED)
                    break

                if not chunk:
                    transfer.update_state(TransferState.COMPLETED)
                    logging.info(f"Transfer {transfer_id}: Finished reading file.")
                    break

                # --- Send Chunk ---
                transfer.transferred_size += len(chunk)
                chunk_message = json.dumps({
                    "type": "file_chunk",
                    "transfer_id": transfer_id,
                    "chunk": chunk.hex()
                })
                disconnected_peers_during_send = []
                for p_ip, websocket in list(peers_to_send_to.items()):
                    try:
                        await websocket.send(chunk_message)
                    except Exception as e:
                        logging.error(f"Transfer {transfer_id}: Error sending chunk to {p_ip}: {e}")
                        # Remove peer if sending fails
                        disconnected_peers_during_send.append(p_ip)

                # Update list of active peers for this transfer
                for p_ip in disconnected_peers_during_send:
                     if p_ip in peers_to_send_to:
                        del peers_to_send_to[p_ip]


                if not peers_to_send_to:
                    logging.warning(f"Transfer {transfer_id}: All peers disconnected during transfer.")
                    transfer.update_state(TransferState.FAILED)
                    break

                # Brief sleep to yield control and manage progress updates
                await asyncio.sleep(0.01)

    except Exception as e:
        logging.exception(f"Transfer {transfer_id}: Unexpected error during file sending: {e}")
        transfer.update_state(TransferState.FAILED)
    finally:
        if transfer.file_handle:
            await transfer.file_handle.close()
            transfer.file_handle = None

    if transfer.state == TransferState.COMPLETED:
        logging.info(f"File transfer {transfer_id} ('{display_name}') completed successfully for remaining peers.")
        await message_queue.put(f"Transfer of '{display_name}' completed.")
    elif transfer.state == TransferState.FAILED:
         logging.warning(f"File transfer {transfer_id} ('{display_name}') failed.")
         await message_queue.put(f"Transfer of '{display_name}' failed.")

    # Final state is set, update_transfer_progress will handle cleanup


async def update_transfer_progress():
    """Update the progress of active file transfers and remove completed/failed ones."""
    while not shutdown_event.is_set():
        try:
            items_to_remove = []
            for transfer_id, transfer in list(active_transfers.items()):
                # Check for final states
                if transfer.state in (TransferState.COMPLETED, TransferState.FAILED, TransferState.DENIED):
                    items_to_remove.append(transfer_id)
                    if transfer.file_handle:
                        try:
                            await transfer.file_handle.close()
                            transfer.file_handle = None
                            logging.debug(f"Closed file handle for finalized transfer {transfer_id}")
                        except Exception as e:
                            logging.error(f"Error closing file handle for transfer {transfer_id}: {e}")
                elif transfer.state == TransferState.IN_PROGRESS and transfer.total_size > 0:
                    progress = (transfer.transferred_size / transfer.total_size) * 100
                    # Limit progress logging frequency if needed
                    logging.debug(f"Transfer {transfer_id} ({transfer.relative_path or transfer.file_path}): {progress:.2f}%")
                # Add logging for other states if helpful (PENDING_APPROVAL, PAUSED)

            # Remove items outside the loop iteration
            if items_to_remove:
                for transfer_id in items_to_remove:
                    if transfer_id in active_transfers:
                        del active_transfers[transfer_id]
                        logging.info(f"Removed transfer {transfer_id} from active_transfers.")

            await asyncio.sleep(1) # Check every second
        except Exception as e:
            logging.exception(f"Error in update_transfer_progress: {e}")
            # Avoid tight loop on error
            await asyncio.sleep(5)