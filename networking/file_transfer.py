import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
from enum import Enum
from networking.shared_state import active_transfers, shutdown_event
import websockets # Import for exception handling

class TransferState(Enum):
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class FileTransfer:
    def __init__(self, file_path, peer_ip, direction="send"):
        self.file_path = file_path
        self.peer_ip = peer_ip
        self.direction = direction
        self.transfer_id = str(uuid.uuid4())
        try:
             self.total_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        except OSError as e:
             logging.error(f"Cannot get size for {file_path}: {e}")
             self.total_size = 0
        self.transferred_size = 0
        self.file_handle = None
        self.state = TransferState.IN_PROGRESS
        self.hash_algo = hashlib.sha256()
        self.expected_hash = None
        self.condition = asyncio.Condition()

    async def pause(self):
        async with self.condition:
            if self.state == TransferState.IN_PROGRESS:
                self.state = TransferState.PAUSED
                logging.info(f"Transfer {self.transfer_id} paused.")

    async def resume(self):
        async with self.condition:
            if self.state == TransferState.PAUSED:
                self.state = TransferState.IN_PROGRESS
                self.condition.notify_all()
                logging.info(f"Transfer {self.transfer_id} resumed.")

async def compute_hash(file_path):
    hash_algo = hashlib.sha256()
    try:
        async with aiofiles.open(file_path, "rb") as f:
            while True:
                chunk = await f.read(1024 * 1024)
                if not chunk:
                    break
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    except OSError as e:
         logging.error(f"Error computing hash for {file_path}: {e}")
         return None
    except Exception as e:
         logging.exception(f"Unexpected error computing hash for {file_path}: {e}")
         return None


async def send_file(file_path, peers):
    transfer_id = str(uuid.uuid4())
    try:
         file_size = os.path.getsize(file_path)
    except OSError as e:
        logging.error(f"Cannot send file {file_path}: {e}")
        await message_queue.put(f"Error sending {os.path.basename(file_path)}: Cannot access file.")
        return

    file_name = os.path.basename(file_path)
    file_hash = await compute_hash(file_path)
    if file_hash is None:
         logging.warning(f"Could not compute hash for {file_path}, sending without integrity check.")
         # Optionally ask user or fail here? For now, proceed without hash.

    transfer = FileTransfer(file_path, list(peers.keys())[0], direction="send")
    transfer.transfer_id = transfer_id
    transfer.total_size = file_size
    transfer.expected_hash = file_hash
    active_transfers[transfer_id] = transfer

    init_message = json.dumps({
        "type": "file_transfer_init",
        "transfer_id": transfer_id,
        "filename": file_name,
        "filesize": file_size,
        "file_hash": file_hash # Send None if hash failed
    })

    connected_peers = {}
    for peer_ip, websocket in peers.items():
        try:
            await websocket.send(init_message)
            connected_peers[peer_ip] = websocket # Add if init send succeeds
        except websockets.exceptions.ConnectionClosed:
             logging.warning(f"Connection closed before sending file init to {peer_ip}")
        except Exception as e:
            logging.error(f"Failed to send file init to {peer_ip}: {e}")

    if not connected_peers:
        logging.error(f"Failed to initiate file transfer {transfer_id} with any peer.")
        if transfer_id in active_transfers: del active_transfers[transfer_id]
        await message_queue.put(f"Error: Could not initiate transfer '{file_name}' with recipient(s).")
        return

    peers = connected_peers # Only send chunks to peers who received init

    try:
        async with aiofiles.open(file_path, "rb") as f:
            transfer.file_handle = f
            chunk_size = 1024 * 1024

            while not shutdown_event.is_set():
                async with transfer.condition:
                    while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                        await transfer.condition.wait()

                    if transfer.state != TransferState.IN_PROGRESS: # If failed/completed/shutdown during pause
                         break
                    if shutdown_event.is_set():
                        transfer.state = TransferState.FAILED # Mark as failed on shutdown? Or let cleanup handle?
                        break

                try:
                    chunk = await f.read(chunk_size)
                except OSError as read_err:
                     logging.error(f"Error reading file chunk for {transfer_id}: {read_err}")
                     transfer.state = TransferState.FAILED
                     break

                if not chunk:
                    transfer.state = TransferState.COMPLETED
                    break

                transfer.transferred_size += len(chunk)

                # Send binary chunk directly
                for peer_ip, websocket in list(peers.items()):
                    try:
                        await websocket.send(chunk) # SEND BINARY
                    except websockets.exceptions.ConnectionClosed:
                        logging.warning(f"Connection to {peer_ip} closed during file transfer {transfer_id}.")
                        del peers[peer_ip]
                    except Exception as send_err:
                        logging.error(f"Error sending chunk to {peer_ip} for {transfer_id}: {send_err}")
                        del peers[peer_ip] # Assume peer is lost on send error

                if not peers:
                    logging.warning(f"All peers disconnected during file transfer {transfer_id}.")
                    transfer.state = TransferState.FAILED
                    break # Exit chunk loop if no peers left

    except OSError as file_err:
         logging.error(f"Error opening/reading file {file_path} for transfer {transfer_id}: {file_err}")
         transfer.state = TransferState.FAILED
    except Exception as e:
         logging.exception(f"Unexpected error during file send for {transfer_id}: {e}")
         transfer.state = TransferState.FAILED
    finally:
        if transfer.file_handle and not transfer.file_handle.closed:
            await transfer.file_handle.close()
            transfer.file_handle = None

    if transfer.state == TransferState.COMPLETED:
        logging.info(f"File sending task {transfer_id} completed.")
    else: # Includes FAILED state
         logging.warning(f"File sending task {transfer_id} finished with state: {transfer.state.value}")
         # Notification handled by update_transfer_progress or disconnect logic


async def update_transfer_progress():
    from networking.messaging import message_queue # Import here to avoid circular dependency
    while not shutdown_event.is_set():
        try:
            processed_ids = set()
            for transfer_id, transfer in list(active_transfers.items()):
                if transfer_id in processed_ids: continue

                notify_user = False
                if transfer.state == TransferState.COMPLETED:
                    logging.info(f"Removing completed transfer {transfer_id}")
                    # User already notified on completion in receive_peer_messages or send_file logged completion
                    if transfer.file_handle and not transfer.file_handle.closed: await transfer.file_handle.close()
                    del active_transfers[transfer_id]
                    processed_ids.add(transfer_id)
                elif transfer.state == TransferState.FAILED:
                    logging.warning(f"Removing failed transfer {transfer_id}")
                    # User should have been notified when failure occurred (e.g., disconnect, hash fail)
                    if transfer.file_handle and not transfer.file_handle.closed: await transfer.file_handle.close()
                    if transfer_id in active_transfers: # Check again, might have been removed by disconnect cleanup
                        del active_transfers[transfer_id]
                    processed_ids.add(transfer_id)
                else:
                    # Log progress for ongoing transfers
                    if transfer.total_size > 0:
                        progress = (transfer.transferred_size / transfer.total_size) * 100
                        logging.debug(f"Transfer {transfer_id} ({transfer.state.value}): {progress:.1f}%")
                    else:
                         logging.debug(f"Transfer {transfer_id} ({transfer.state.value}): Size 0 or unknown")

            await asyncio.sleep(1)
        except Exception as e: # Catch broad exceptions in background task is safer
            logging.exception(f"Error in update_transfer_progress: {e}")
            await asyncio.sleep(5) # Wait longer after error