import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
from enum import Enum
from networking.shared_state import active_transfers, shutdown_event
from networking.shared_state import active_transfers, shutdown_event, active_transfers_lock, message_queue 
import websockets 
MAX_CHUNK_SIZE = 8 * 1024 * 1024
MAX_TRANSFER_RETRIES = 3
RETRY_BACKOFF_BASE = 2 
peers_to_notify_completion = {} 


class TransferState(Enum):
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown" 
    STARTING = "starting"  

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

MAX_CONCURRENT_TRANSFERS = 5
transfer_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TRANSFERS)

async def send_file(file_path, initial_peers, retry_count=0):
    async with transfer_semaphore:
        transfer_id = str(uuid.uuid4())
        file_name = os.path.basename(file_path) 
        if retry_count >= MAX_TRANSFER_RETRIES:
            logging.error(f"Failed to send {file_name} after {MAX_TRANSFER_RETRIES} attempts (Transfer ID: {transfer_id}).")
            async with active_transfers_lock:
                if transfer_id in active_transfers:
                    active_transfers[transfer_id].state = TransferState.FAILED
                    active_transfers[transfer_id].error_message = f"Failed after {MAX_TRANSFER_RETRIES} retries."
                else:
                    await message_queue.put(f"Failed to send '{file_name}' after {MAX_TRANSFER_RETRIES} attempts.")
            return

        logging.info(f"Attempting to send file: {file_name} (Transfer ID: {transfer_id}, Attempt: {retry_count + 1}/{MAX_TRANSFER_RETRIES})")

        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            logging.error(f"Cannot send file {file_path} (Transfer ID: {transfer_id}): {e}")
            await message_queue.put(f"Error sending '{file_name}': Cannot access file.")
            return

        async with active_transfers_lock:
            if transfer_id in active_transfers and retry_count > 0:
                transfer = active_transfers[transfer_id]
                transfer.state = TransferState.STARTING
                transfer.transferred_size = 0
                transfer.error_message = None
                logging.info(f"Retrying transfer {transfer_id}. Resetting state.")
            else:
                file_hash = await compute_hash(file_path)
                if file_hash is None:
                    logging.warning(f"Could not compute hash for {file_path} (Transfer ID: {transfer_id}), sending without integrity check.")

                transfer = FileTransfer(file_path, "multiple_peers", direction="send") 
                transfer.transfer_id = transfer_id
                transfer.total_size = file_size
                transfer.expected_hash = file_hash
                transfer.state = TransferState.STARTING
                active_transfers[transfer_id] = transfer


        init_message = json.dumps({
            "type": "file_transfer_init",
            "transfer_id": transfer_id,
            "filename": file_name,
            "filesize": file_size,
            "file_hash": transfer.expected_hash 
        })

        connected_peers = {}
        peers_to_notify = []
        current_peers_dict = initial_peers
        for peer_ip, websocket in current_peers_dict.items():
            try:
                await websocket.send(init_message)
                connected_peers[peer_ip] = websocket
                peers_to_notify.append(peer_ip)
                logging.info(f"Sent transfer init {transfer_id} for {file_name} to {peer_ip} (Attempt {retry_count+1})")
            except websockets.exceptions.ConnectionClosed:
                logging.warning(f"Connection closed before sending file init to {peer_ip} for {transfer_id} (Attempt {retry_count+1})")
            except Exception as e:
                logging.error(f"Failed to send file init to {peer_ip} for {transfer_id} (Attempt {retry_count+1}): {e}")

        if not connected_peers:
            logging.error(f"Failed to initiate file transfer {transfer_id} with any peer (Attempt {retry_count+1}).")
            is_retryable_init_failure = False 
            if is_retryable_init_failure and retry_count < MAX_TRANSFER_RETRIES -1: 
                retry_delay = RETRY_BACKOFF_BASE ** retry_count
                logging.warning(f"Initiation failed for {transfer_id}. Retrying in {retry_delay}s...")
                await message_queue.put(f"Transfer initiation failed for '{file_name}'. Retrying in {retry_delay}s... ({retry_count+2}/{MAX_TRANSFER_RETRIES})")
                await asyncio.sleep(retry_delay)
                await send_file(file_path, initial_peers, retry_count + 1)
                return 
            else:
                async with active_transfers_lock:
                    if transfer_id in active_transfers:
                        active_transfers[transfer_id].state = TransferState.FAILED
                        active_transfers[transfer_id].error_message = "No peers connected for transfer"
                await message_queue.put(f"Error: Could not initiate transfer '{file_name}' with recipient(s).")
                return


        transfer.peers = list(connected_peers.keys())
        transfer.state = TransferState.IN_PROGRESS
        peers_for_chunks = connected_peers.copy()
        send_interrupted = False

        try:
            async with aiofiles.open(file_path, "rb") as f:
                transfer.file_handle = f 
                chunk_size = MAX_CHUNK_SIZE

                while not shutdown_event.is_set():
                    async with transfer.condition:
                        while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                            logging.debug(f"Transfer {transfer_id} is paused, waiting.")
                            await transfer.condition.wait()

                        if shutdown_event.is_set():
                            logging.info(f"Shutdown signaled during send for {transfer_id}.")
                            transfer.state = TransferState.FAILED
                            transfer.error_message = "Transfer cancelled due to shutdown"
                            send_interrupted = True 
                            break

                        if transfer.state == TransferState.FAILED:
                            logging.warning(f"Transfer {transfer_id} marked FAILED externally, stopping send loop.")
                            send_interrupted = True 
                            break
                        if transfer.state == TransferState.COMPLETED:
                            logging.info(f"Transfer {transfer_id} marked COMPLETED externally, stopping send loop.")
                            break
                        if transfer.state != TransferState.IN_PROGRESS:
                            logging.warning(f"Transfer {transfer_id} in unexpected state {transfer.state.value} during send, stopping.")
                            transfer.state = TransferState.FAILED
                            transfer.error_message = f"Unexpected state {transfer.state.value}"
                            send_interrupted = True
                            break

                    try:
                        chunk = await f.read(chunk_size)
                    except OSError as read_err:
                        logging.error(f"Error reading file chunk for {transfer_id}: {read_err}")
                        transfer.state = TransferState.FAILED 
                        transfer.error_message = f"File read error: {read_err}"
                        send_interrupted = True
                        raise read_err 

                    if not chunk:
                        if transfer.state != TransferState.COMPLETED: 
                            transfer.state = TransferState.COMPLETED
                            logging.info(f"Finished reading file for transfer {transfer_id}")
                        break 

                    current_chunk_size = len(chunk)
                    transfer.transferred_size += current_chunk_size

                    disconnected_peers_in_chunk = []
                    for peer_ip, websocket in list(peers_for_chunks.items()):
                        try:
                            await websocket.send(chunk)
                        except websockets.exceptions.ConnectionClosed as conn_err:
                            logging.warning(f"Connection to {peer_ip} closed during file transfer {transfer_id}. Removing peer.")
                            disconnected_peers_in_chunk.append(peer_ip)
                            del peers_for_chunks[peer_ip]
                        except Exception as send_err:
                            logging.error(f"Error sending chunk to {peer_ip} for {transfer_id}: {send_err}. Removing peer.")
                            disconnected_peers_in_chunk.append(peer_ip)
                            del peers_for_chunks[peer_ip]

                    if disconnected_peers_in_chunk:
                        async with active_transfers_lock:
                            if transfer_id in active_transfers:
                                current_peers = active_transfers[transfer_id].peers
                                active_transfers[transfer_id].peers = [p for p in current_peers if p not in disconnected_peers_in_chunk]

                    if not peers_for_chunks:
                        logging.warning(f"All peers disconnected during file transfer {transfer_id}.")
                        transfer.state = TransferState.FAILED
                        transfer.error_message = "All recipients disconnected"
                        send_interrupted = True
                        raise websockets.exceptions.ConnectionClosed("All peers disconnected during transfer")


        except (websockets.exceptions.ConnectionClosed, OSError) as network_or_file_err:
            logging.warning(f"Network/File error during file transfer {transfer_id}, attempt {retry_count+1}: {network_or_file_err}")
            send_interrupted = True 

        except Exception as e:
            logging.exception(f"Unexpected error during file send loop for {transfer_id}: {e}")
            async with active_transfers_lock:
                if transfer_id in active_transfers:
                    active_transfers[transfer_id].state = TransferState.FAILED
                    active_transfers[transfer_id].error_message = f"Unexpected send error: {e}"
            send_interrupted = True 

        finally:
            if hasattr(transfer, 'file_handle') and transfer.file_handle and not transfer.file_handle.closed:
                try:
                    await transfer.file_handle.close()
                    logging.debug(f"Closed file handle for sender {transfer_id} after attempt {retry_count + 1}")
                    transfer.file_handle = None
                except Exception as close_err:
                    logging.error(f"Error closing sender file handle for {transfer_id} after attempt {retry_count + 1}: {close_err}")

        if send_interrupted and transfer.state == TransferState.FAILED and not shutdown_event.is_set():
            is_retryable_error = isinstance(transfer.error_message, str) and \
                                ("disconnected" in transfer.error_message.lower() or \
                                "read error" in transfer.error_message.lower()) 

            if is_retryable_error and retry_count < MAX_TRANSFER_RETRIES -1: 
                retry_delay = RETRY_BACKOFF_BASE ** retry_count
                logging.warning(f"Transfer {transfer_id} interrupted. Retrying in {retry_delay}s...")
                await message_queue.put(f"Transfer '{file_name}' interrupted. Retrying in {retry_delay}s... ({retry_count+2}/{MAX_TRANSFER_RETRIES})")
                await asyncio.sleep(retry_delay)

                await send_file(file_path, initial_peers, retry_count + 1)
                return 
            elif not is_retryable_error:
                logging.error(f"Transfer {transfer_id} failed with non-retryable error: {transfer.error_message}")
                await message_queue.put(f"Failed to send '{file_name}'. Reason: {transfer.error_message}")
                return
            else: 
                logging.error(f"Failed to send {file_name} (Transfer ID: {transfer_id}) after {MAX_TRANSFER_RETRIES} attempts due to: {transfer.error_message}")
                await message_queue.put(f"Failed to send '{file_name}' after {MAX_TRANSFER_RETRIES} attempts.")
                return

        final_state = TransferState.UNKNOWN
        final_error = "Unknown"
        async with active_transfers_lock:
            if transfer_id in active_transfers:
                final_state = active_transfers[transfer_id].state
                final_error = active_transfers[transfer_id].error_message

        if final_state == TransferState.COMPLETED:
            logging.info(f"File sending task {transfer_id} ({file_name}) completed successfully on attempt {retry_count + 1}.")
            await message_queue.put(f"Successfully sent '{file_name}'.")
            completion_message = json.dumps({"type": "transfer_complete", "transfer_id": transfer_id})

            if not peers_to_notify_completion and connected_peers:
                peers_to_notify_completion = connected_peers 

            for peer_ip, websocket in peers_to_notify_completion.items():
                try:
                    await websocket.send(completion_message)
                except Exception as final_send_err:
                    logging.warning(f"Failed to send completion message to {peer_ip} for {transfer_id}: {final_send_err}")

        elif final_state == TransferState.FAILED:
            logging.warning(f"File sending task {transfer_id} ({file_name}) ended with state: {final_state.value}. Reason: {final_error}")
            if not send_interrupted: 
                await message_queue.put(f"Failed to send '{file_name}'. Reason: {final_error}")

async def update_transfer_progress():
    logging.info("Starting transfer progress updater task.")
    try:
        while not shutdown_event.is_set():
            try:
                processed_ids = set()
                async with active_transfers_lock:
                    transfers_to_process = list(active_transfers.items())

                for transfer_id, transfer in transfers_to_process:
                    if transfer_id in processed_ids:
                        continue

                    try:
                        if transfer.state == TransferState.COMPLETED:
                            logging.info(f"Removing completed transfer {transfer_id} (State: {transfer.state.value})")
                            if transfer.file_handle and not transfer.file_handle.closed:
                                try:
                                    await transfer.file_handle.close()
                                    logging.debug(f"Closed file handle for completed transfer {transfer_id}")
                                except Exception as fh_e:
                                    logging.error(f"Error closing file handle for completed transfer {transfer_id}: {fh_e}")

                            async with active_transfers_lock:
                                if transfer_id in active_transfers:
                                    del active_transfers[transfer_id]
                                    processed_ids.add(transfer_id)
                                else:
                                    logging.warning(f"Completed transfer {transfer_id} already removed before cleanup.")

                        elif transfer.state == TransferState.FAILED:
                            error_msg = getattr(transfer, 'error_message', 'No reason specified')
                            logging.warning(f"Removing failed transfer {transfer_id} (State: {transfer.state.value}, Reason: {error_msg})")
                            if transfer.file_handle and not transfer.file_handle.closed:
                                try:
                                    await transfer.file_handle.close()
                                    logging.debug(f"Closed file handle for failed transfer {transfer_id}")
                                except Exception as fh_e:
                                    logging.error(f"Error closing file handle for FAILED transfer {transfer_id}: {fh_e}")

                            async with active_transfers_lock:
                                if transfer_id in active_transfers:
                                    del active_transfers[transfer_id]
                                    processed_ids.add(transfer_id)
                                else:
                                    logging.warning(f"Failed transfer {transfer_id} already removed before cleanup.")

                        else: 
                            filename = getattr(transfer, 'filename', 'unknown_file')
                            if hasattr(transfer, 'total_size') and transfer.total_size > 0:
                                current_transferred = max(0, getattr(transfer, 'transferred_size', 0))
                                current_total = max(1, transfer.total_size)
                                progress = (current_transferred / current_total) * 100
                                logging.debug(f"Transfer {transfer_id} ({filename}, {transfer.state.value}): {current_transferred}/{current_total} bytes ({progress:.1f}%)")
                            elif hasattr(transfer, 'transferred_size') and transfer.transferred_size > 0:
                                logging.debug(f"Transfer {transfer_id} ({filename}, {transfer.state.value}): {transfer.transferred_size} bytes transferred (total size unknown)")
                            else:
                                size_info = getattr(transfer, 'total_size', 'unknown')
                                logging.debug(f"Transfer {transfer_id} ({filename}, {transfer.state.value}): Awaiting progress (Size {size_info})")

                    except AttributeError as ae:
                        logging.error(f"Attribute error processing transfer {transfer_id}: {ae}. Transfer object state: {getattr(transfer, 'state', 'unknown')}")
                        async with active_transfers_lock:
                            if transfer_id in active_transfers:
                                logging.warning(f"Removing potentially corrupt transfer {transfer_id} due to attribute error.")
                                if hasattr(transfer, 'file_handle') and transfer.file_handle and not transfer.file_handle.closed:
                                    try: await transfer.file_handle.close()
                                    except Exception: pass
                                del active_transfers[transfer_id]
                                processed_ids.add(transfer_id)
                    except Exception as inner_e:
                        logging.exception(f"Error processing individual transfer {transfer_id}: {inner_e}")

                await asyncio.sleep(1)

            except asyncio.CancelledError:
                logging.info("update_transfer_progress task cancelled.")
                raise
            except Exception as e:
                logging.exception(f"Error in update_transfer_progress loop iteration: {e}")
                await asyncio.sleep(5)

    finally:
        logging.info("Transfer progress monitoring exiting, ensuring final cleanup...")
        async with active_transfers_lock:
            remaining_ids = list(active_transfers.keys())
            if remaining_ids:
                logging.warning(f"Performing final cleanup for {len(remaining_ids)} transfers remaining upon exit.")
            for transfer_id in remaining_ids:
                 transfer = active_transfers.get(transfer_id)
                 logging.warning(f"Force-closing transfer {transfer_id} during final cleanup.")
                 if transfer and hasattr(transfer, 'file_handle') and transfer.file_handle and not transfer.file_handle.closed:
                     try:
                         await transfer.file_handle.close()
                     except Exception as fh_e:
                         logging.error(f"Error during final cleanup close for {transfer_id}: {fh_e}")
        logging.info("Final transfer cleanup attempt complete.")