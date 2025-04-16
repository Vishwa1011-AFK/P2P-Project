import asyncio
import os
import uuid
import aiofiles
import hashlib
import logging
import json
import time
import websockets
from enum import Enum

from networking.shared_state import (
    active_transfers, shutdown_event, message_queue,
    active_transfers_lock, outgoing_transfers_by_peer
)
from websockets.connection import State
from utils.file_validation import check_file_size, check_disk_space, safe_close_file

logger = logging.getLogger(__name__)

class TransferState(Enum):
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class FileTransfer:
    def __init__(self, file_path, peer_ip, direction="send", transfer_id=None):
        self.file_path = file_path
        self.peer_ip = peer_ip
        self.direction = direction
        self.transfer_id = transfer_id if transfer_id else str(uuid.uuid4())
        self.total_size = 0
        self.transferred_size = 0
        self.file_handle = None
        self.state = TransferState.IN_PROGRESS
        self.hash_algo = hashlib.sha256()
        self.expected_hash = None
        self.condition = asyncio.Condition()
        self.start_time = time.time()
        try:
            if direction == "send" and os.path.exists(file_path):
                self.total_size = os.path.getsize(file_path)
        except OSError as e:
            logger.error(f"Error getting size for {file_path}: {e}")
            self.state = TransferState.FAILED

    async def pause(self):
        async with self.condition:
            if self.state == TransferState.IN_PROGRESS:
                self.state = TransferState.PAUSED
                logger.info(f"Transfer {self.transfer_id[:8]} ({self.direction}) paused.")
                await message_queue.put({"type": "transfer_update"})

    async def resume(self):
        async with self.condition:
            if self.state == TransferState.PAUSED:
                self.state = TransferState.IN_PROGRESS
                logger.info(f"Transfer {self.transfer_id[:8]} ({self.direction}) resumed.")
                self.condition.notify_all()
                await message_queue.put({"type": "transfer_update"})

    async def fail(self, reason="Unknown"):
        async with self.condition:
             if self.state not in [TransferState.COMPLETED, TransferState.FAILED]:
                logger.error(f"Transfer {self.transfer_id[:8]} ({self.direction}) failed: {reason}")
                original_state = self.state
                self.state = TransferState.FAILED
                if self.file_handle:
                    await safe_close_file(self.file_handle)
                    self.file_handle = None
                if original_state == TransferState.PAUSED:
                    self.condition.notify_all()
                await message_queue.put({"type": "transfer_update"})

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
    except FileNotFoundError:
        logger.error(f"File not found during hash computation: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error computing hash for {file_path}: {e}", exc_info=True)
        return None

async def send_file(file_path, peers):
    if not os.path.isfile(file_path):
        await message_queue.put({"type": "log", "message": f"Send Error: File not found '{file_path}'", "level": logging.ERROR})
        return
    if not peers:
        await message_queue.put({"type": "log", "message": "Send Error: No peer specified.", "level": logging.ERROR})
        return

    is_valid, message = check_file_size(file_path)
    if not is_valid:
        await message_queue.put({"type": "log", "message": f"Send Error: {message}", "level": logging.ERROR})
        return

    peer_ip, websocket = next(iter(peers.items()))
    if not websocket or websocket.state != State.OPEN:
         await message_queue.put({"type": "log", "message": f"Send Error: Peer {peer_ip} not connected.", "level": logging.ERROR})
         return

    async with active_transfers_lock:
        if peer_ip in outgoing_transfers_by_peer:
            existing_transfer_id = outgoing_transfers_by_peer[peer_ip]
            await message_queue.put({
                "type": "log",
                "message": f"Send Error: Already sending file to {peer_ip} (ID: {existing_transfer_id[:8]}). Wait or cancel.",
                "level": logging.ERROR
            })
            return

    transfer_id = str(uuid.uuid4())
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    file_hash = await compute_hash(file_path)

    if file_hash is None:
        await message_queue.put({"type": "log", "message": f"Send Error: Could not compute hash for '{file_name}'.", "level": logging.ERROR})
        return

    transfer = FileTransfer(file_path, peer_ip, direction="send", transfer_id=transfer_id)
    if transfer.state == TransferState.FAILED:
         await message_queue.put({"type": "log", "message": f"Send Error: Could not initialize transfer for '{file_name}'.", "level": logging.ERROR})
         return

    transfer.total_size = file_size
    transfer.expected_hash = file_hash

    async with active_transfers_lock:
        outgoing_transfers_by_peer[peer_ip] = transfer_id
        active_transfers[transfer_id] = transfer

    await message_queue.put({"type": "transfer_update"})
    await message_queue.put({"type": "log", "message": f"Starting send '{file_name}' to {peer_ip} (ID: {transfer_id[:8]})"})

    init_message = json.dumps({
        "type": "file_transfer_init", "transfer_id": transfer_id,
        "filename": file_name, "filesize": file_size, "file_hash": file_hash
    })

    try:
        if websocket.state != State.OPEN:
            raise websockets.exceptions.ConnectionClosedError(1001, "Peer disconnected before init")
        await websocket.send(init_message)
        logger.debug(f"Sent file_transfer_init for {transfer_id[:8]} to {peer_ip}")

    except Exception as e:
        logger.error(f"Failed to send file init to {peer_ip}: {e}")
        async with active_transfers_lock:
            active_transfers.pop(transfer_id, None)
            if outgoing_transfers_by_peer.get(peer_ip) == transfer_id:
                 outgoing_transfers_by_peer.pop(peer_ip, None)
        await message_queue.put({"type": "transfer_update"})
        await message_queue.put({"type": "log", "message": f"Send Error: Failed to initiate transfer with {peer_ip}.", "level": logging.ERROR})
        return

    try:
        async with aiofiles.open(file_path, "rb") as f:
            transfer.file_handle = f
            chunk_size = 1024 * 1024
            last_yield_time = time.monotonic()

            while not shutdown_event.is_set() and transfer.state != TransferState.FAILED:
                current_state = TransferState.FAILED
                try:
                    async with transfer.condition:
                        current_state = transfer.state
                except Exception as state_err:
                     logger.error(f"Error getting transfer state for {transfer_id[:8]}: {state_err}")
                     await transfer.fail(f"State error: {state_err}")
                     break

                if current_state == TransferState.PAUSED:
                    logger.debug(f"Transfer {transfer_id[:8]} is paused. Sending signal and waiting.")
                    try:
                        if websocket.state != State.OPEN:
                            logger.warning(f"Cannot send PAUSE for {transfer_id[:8]}, peer {peer_ip} disconnected.")
                            await transfer.fail("Peer disconnected during pause")
                            break

                        pause_msg = json.dumps({"type": "TRANSFER_PAUSE", "transfer_id": transfer_id})
                        await websocket.send(pause_msg)
                        logger.info(f"Sent PAUSE signal for {transfer_id[:8]} to {peer_ip}")

                        async with transfer.condition:
                            while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                                try:
                                    await asyncio.wait_for(transfer.condition.wait(), timeout=5.0)
                                except asyncio.TimeoutError:
                                    if websocket.state != State.OPEN:
                                        logger.warning(f"Peer {peer_ip} disconnected while waiting for resume (timeout).")
                                        await transfer.fail("Peer disconnected while paused")
                                        break
                                    continue

                            if transfer.state == TransferState.FAILED:
                                break

                        if transfer.state == TransferState.FAILED: break

                        if transfer.state == TransferState.IN_PROGRESS and not shutdown_event.is_set():
                            if websocket.state != State.OPEN:
                                logger.warning(f"Cannot send RESUME for {transfer_id[:8]}, peer {peer_ip} disconnected.")
                                await transfer.fail("Peer disconnected before resume signal")
                                break

                            resume_msg = json.dumps({"type": "TRANSFER_RESUME", "transfer_id": transfer_id})
                            await websocket.send(resume_msg)
                            logger.info(f"Sent RESUME signal for {transfer_id[:8]} to {peer_ip}")
                        elif shutdown_event.is_set():
                            logger.info(f"Shutdown while paused {transfer_id[:8]}")
                            break

                    except Exception as signal_err:
                         logger.error(f"Error sending PAUSE/RESUME signal for {transfer_id[:8]}: {signal_err}", exc_info=True)
                         await transfer.fail(f"Signaling error: {signal_err}")
                         break
                    continue

                elif current_state == TransferState.IN_PROGRESS:
                    try:
                        chunk = await f.read(chunk_size)
                        if not chunk:
                            await asyncio.sleep(0.1)
                            if transfer.state != TransferState.FAILED:
                                transfer.state = TransferState.COMPLETED
                            logger.debug(f"Reached EOF for {transfer_id[:8]}. Final state: {transfer.state}")
                            break

                        if websocket.state != State.OPEN:
                             logger.warning(f"Peer {peer_ip} disconnected before sending chunk.")
                             await transfer.fail("Peer disconnected during send")
                             break

                        await websocket.send(chunk)
                        transfer.transferred_size += len(chunk)

                        current_time = time.monotonic()
                        if current_time - last_yield_time > 0.1:
                           await asyncio.sleep(0)
                           last_yield_time = current_time

                    except (websockets.exceptions.ConnectionClosedOK, websockets.exceptions.ConnectionClosedError) as conn_err:
                         logger.warning(f"Connection closed during send for {transfer_id[:8]}: {conn_err}")
                         await transfer.fail(f"Connection closed: {conn_err.reason}")
                         break
                    except Exception as send_err:
                        logger.error(f"Error sending chunk for {transfer_id[:8]}: {send_err}", exc_info=True)
                        await transfer.fail(f"Send error: {send_err}")
                        break

                elif current_state in (TransferState.FAILED, TransferState.COMPLETED):
                     logger.debug(f"Transfer {transfer_id[:8]} loop exiting due to state: {current_state}")
                     break

                else:
                     logger.error(f"Unexpected transfer state {current_state} for {transfer_id[:8]}. Failing.")
                     await transfer.fail(f"Unexpected state: {current_state}")
                     break

    except Exception as e:
        logger.exception(f"Error during file send processing for {transfer_id[:8]}")
        if transfer.state not in (TransferState.FAILED, TransferState.COMPLETED):
             await transfer.fail(f"Send processing error: {e}")
    finally:
        logger.debug(f"Entering finally block for send_file {transfer_id[:8]}. Final state: {transfer.state}")
        if transfer.file_handle:
            await safe_close_file(transfer.file_handle)
            transfer.file_handle = None

        final_state = transfer.state
        if final_state == TransferState.COMPLETED:
            logger.info(f"File transfer {transfer_id[:8]} completed sending.")
            await message_queue.put({"type": "log", "message": f"Sent '{file_name}' successfully."})
        elif shutdown_event.is_set() and final_state != TransferState.FAILED:
             logger.info(f"Send {transfer_id[:8]} cancelled by shutdown.")
             await message_queue.put({"type": "log", "message": f"Send '{file_name}' cancelled by shutdown."})
             await transfer.fail("Shutdown initiated")
        elif final_state == TransferState.FAILED:
             logger.warning(f"File transfer {transfer_id[:8]} ended in FAILED state.")

        await message_queue.put({"type": "transfer_update"})

        async with active_transfers_lock:
            if outgoing_transfers_by_peer.get(peer_ip) == transfer_id:
                outgoing_transfers_by_peer.pop(peer_ip, None)
                logger.debug(f"Removed {transfer_id[:8]} from outgoing tracking for {peer_ip}")

async def update_transfer_progress():
    while not shutdown_event.is_set():
        try:
            transfers_to_remove = []
            updated = False
            current_active_transfers = {}

            async with active_transfers_lock:
                current_active_transfers = dict(active_transfers)

            for transfer_id, transfer in current_active_transfers.items():
                async with transfer.condition:
                    current_state = transfer.state

                if current_state in (TransferState.COMPLETED, TransferState.FAILED):
                    transfers_to_remove.append(transfer_id)
                    updated = True
                elif current_state == TransferState.IN_PROGRESS and transfer.total_size > 0:
                    progress = int((transfer.transferred_size / transfer.total_size) * 100)
                    await message_queue.put({
                        "type": "transfer_progress",
                        "transfer_id": transfer_id,
                        "progress": progress
                    })
                elif current_state == TransferState.PAUSED:
                    updated = True

            if transfers_to_remove:
                removed_count = 0
                async with active_transfers_lock:
                    for tid in transfers_to_remove:
                        if tid in active_transfers:
                            transfer_to_remove = active_transfers[tid]
                            async with transfer_to_remove.condition:
                                final_state_check = transfer_to_remove.state

                            if final_state_check in (TransferState.COMPLETED, TransferState.FAILED):
                                if transfer_to_remove.direction == "send":
                                    peer_ip_remove = transfer_to_remove.peer_ip
                                    if outgoing_transfers_by_peer.get(peer_ip_remove) == tid:
                                        outgoing_transfers_by_peer.pop(peer_ip_remove, None)

                                if transfer_to_remove.file_handle:
                                     logger.warning(f"File handle for {tid[:8]} still open during cleanup. Closing.")
                                     await safe_close_file(transfer_to_remove.file_handle)
                                     transfer_to_remove.file_handle = None

                                del active_transfers[tid]
                                removed_count += 1
                                logger.info(f"Removed finished/failed transfer {tid[:8]} from active list.")
                        else:
                            logger.debug(f"Transfer {tid[:8]} already removed while processing removal list.")

                if removed_count > 0:
                    await message_queue.put({"type": "transfer_update"})

            elif updated:
                await message_queue.put({"type": "transfer_update"})

            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            logger.info("update_transfer_progress task cancelled.")
            break
        except Exception as e:
            logger.exception(f"Error in update_transfer_progress: {e}")
            await asyncio.sleep(5)

    logger.info("update_transfer_progress stopped.")
