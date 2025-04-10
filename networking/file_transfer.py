import os
import uuid
import enum
import asyncio
import aiofiles
import json # Added import
from networking.shared_state import active_transfers, message_queue, connections
from networking.messaging.helpers import get_peer_display_name

class TransferState(enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class FileTransfer:
    def __init__(self, peer_ip, direction, file_path, total_size, transfer_id=None, folder_id=None):
        self.peer_ip = peer_ip
        self.direction = direction
        self.file_path = file_path
        self.total_size = total_size
        self.transfer_id = transfer_id or str(uuid.uuid4())
        self.transferred_size = 0
        self.state = TransferState.PENDING
        self.file_handle = None
        self.folder_id = folder_id
        self.initiator = None

    async def pause(self, initiator):
        if self.state == TransferState.IN_PROGRESS:
            self.state = TransferState.PAUSED
            self.initiator = initiator
            if self.direction == "receive" and self.file_handle and not self.file_handle.closed:
                await self.file_handle.close()
                self.file_handle = None

    async def resume(self, initiator):
        if self.state == TransferState.PAUSED and self.initiator == initiator:
            self.state = TransferState.IN_PROGRESS
            if self.direction == "receive":
                # Ensure directory exists before opening in append mode
                os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
                self.file_handle = await aiofiles.open(self.file_path, "ab")


async def request_file_transfer(file_path, peers_dict):
    """Sends the initial file transfer request to peers."""
    try:
        total_size = os.path.getsize(file_path)
    except FileNotFoundError:
         await message_queue.put(f"Error: File not found '{file_path}'")
         return None
    except OSError as e:
         await message_queue.put(f"Error accessing file '{file_path}': {e}")
         return None

    transfer_id = str(uuid.uuid4())

    # Create ONE transfer object for sending, linked to potentially multiple peers
    # Note: Handling individual peer acceptance/rejection might require more complex state
    # For now, assume the first peer dictates the primary peer_ip for the transfer object.
    # This might need refinement if sending to multiple requires separate tracking.
    first_peer_ip = next(iter(peers_dict.keys()), None)
    if not first_peer_ip:
         await message_queue.put("Error: No valid peers to send file to.")
         return None

    file_transfer = FileTransfer(first_peer_ip, "send", file_path, total_size, transfer_id)
    active_transfers[transfer_id] = file_transfer


    request_message = json.dumps({
        "type": "FILE_TRANSFER",
        "transfer_id": transfer_id,
        "file_path": os.path.basename(file_path), # Send only basename
        "file_size": total_size
    })

    sent_to_peers = []
    for peer_ip, websocket in peers_dict.items():
        if websocket and websocket.state == websockets.connection.State.OPEN:
            try:
                await websocket.send(request_message)
                sent_to_peers.append(get_peer_display_name(peer_ip))
            except Exception as e:
                logging.error(f"Failed to send file transfer request to {get_peer_display_name(peer_ip)}: {e}")
        else:
             logging.warning(f"Skipping file transfer request to {get_peer_display_name(peer_ip)}: Not connected or connection closed.")

    if sent_to_peers:
        recipients_str = ", ".join(sent_to_peers)
        await message_queue.put(f"Requested to send '{os.path.basename(file_path)}' ({total_size / (1024 * 1024):.2f} MB) to {recipients_str}. Waiting for approval...")
        return transfer_id # Return ID for tracking
    else:
        await message_queue.put(f"Failed to initiate file transfer request for '{os.path.basename(file_path)}'. No connected peers available.")
        if transfer_id in active_transfers: # Clean up if failed immediately
             del active_transfers[transfer_id]
        return None

# send_file is now effectively request_file_transfer
# The actual sending of chunks happens in networking.messaging.utils.send_file_chunks
# Triggered after receiving FILE_TRANSFER_RESPONSE approval.
send_file = request_file_transfer