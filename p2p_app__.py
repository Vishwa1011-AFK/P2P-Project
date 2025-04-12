import asyncio
import json
import logging
import os
import sys
import uuid
from enum import Enum
import hashlib
import netifaces
import traceback
import time
from collections import defaultdict # For chat histories
from PyQt6.QtCore import QEvent # Ensure QEvent is imported
import threading # Make sure threading is imported

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError as crypto_err:
    print(f"CRITICAL ERROR: Failed to import cryptography: {crypto_err}")
    print("Please install it: pip install cryptography")
    sys.exit(1)

# --- PyQt Imports ---
try:
    from PyQt6.QtCore import (QCoreApplication, QObject, QRunnable, QSettings,
    QThreadPool, pyqtSignal, pyqtSlot, Qt, QThread, QTimer, QSize)
    from PyQt6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QLabel,
    QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMessageBox, QPushButton,
    QProgressBar, QVBoxLayout, QWidget, QTabWidget,
    QTextEdit, QHBoxLayout, QStatusBar, QMenuBar, QMenu,
    QStyle, QSplitter, QStackedWidget, QFrame)
    from PyQt6.QtGui import QIcon, QFont, QCloseEvent, QPalette, QColor, QTextCursor
except ImportError as pyqt_err:
    print(f"CRITICAL ERROR: Failed to import PyQt6: {pyqt_err}")
    print("Please install it: pip install PyQt6")
    sys.exit(1)


# --- Logging Setup (Early) --- #
log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
root_logger = logging.getLogger()
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
if not root_logger.hasHandlers(): root_logger.addHandler(console_handler)
root_logger.setLevel(logging.INFO)
logging.getLogger("websockets").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.INFO)
logger = logging.getLogger("P2PChatApp")

# --- ACTUAL Networking Imports --- #
try:
    logger.debug("Attempting to import networking modules...")
    from networking.discovery import PeerDiscovery

    # --- Corrected Imports ---
    # Import core messaging functions from networking.messaging
    from networking.messaging import (
        handle_incoming_connection, receive_peer_messages, send_message_to_peers,
        maintain_peer_list, initialize_user_config, # Moved initialize_user_config here too
        connect_to_peer, disconnect_from_peer # Moved connect/disconnect here
    )
    # Import connection state directly if needed (or rely on messaging module using it)
    from networking.shared_state import connections

    import websockets
    # Assuming handle_peer_connection uses the functions above, import from main is okay
    from main import handle_peer_connection as actual_handle_peer_connection
    logger.debug("Imported handle_peer_connection")

    # Import utils functions directly from networking.utils
    from networking.utils import (
         get_peer_display_name, resolve_peer_target, get_own_display_name
    )
    # Import group functions directly from networking.groups
    from networking.groups import (
         send_group_create_message, send_group_invite_message, send_group_invite_response,
         send_group_join_request, send_group_join_response, send_group_update_message
    )
    # --- End Corrected Imports ---

    from networking.file_transfer import (
        send_file, FileTransfer, TransferState, compute_hash, update_transfer_progress
    )
    from networking.shared_state import (
        peer_usernames, peer_device_ids, peer_public_keys, shutdown_event,
        user_data, active_transfers, message_queue, groups, pending_invites,
        pending_join_requests, pending_approvals, connection_denials
    )
    NETWORKING_AVAILABLE = True
    logger.info("Successfully imported networking modules.")



except ImportError as e:
    # --- Dummy Fallbacks (Minimal Definitions) --- #
    print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print(f"ERROR: Could not import networking modules: {e}")
    print(f"       Running GUI in dummy mode with limited functionality.")
    print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    NETWORKING_AVAILABLE = False
    logger = logging.getLogger("P2PChatApp_Dummy")
    peer_usernames = {}; peer_device_ids = {}; peer_public_keys = {}; connections = {}; active_transfers = {}
    shutdown_event = asyncio.Event(); user_data = {}; message_queue = asyncio.Queue(); pending_approvals = {}
    connection_denials = {}; groups = defaultdict(lambda: {"admin": None, "members": set()})
    pending_invites = []; pending_join_requests = defaultdict(list)
    class PeerDiscovery:
        def __init__(self): self.peer_list={}; self.own_ip = "127.0.0.1"
        def stop(self): pass
        async def send_broadcasts(self): await asyncio.sleep(3600)
        async def receive_broadcasts(self): await asyncio.sleep(3600)
        async def cleanup_stale_peers(self): await asyncio.sleep(3600)
    async def initialize_user_config(): logger.info("Dummy Init User Config"); user_data.update({'original_username':'Dummy','device_id':'dummy123'})
    def get_peer_display_name(ip): return f"DummyPeer_{ip or 'Unknown'}"
    def get_own_display_name(): return "You(dummy)"
    async def dummy_serve(*args, **kwargs): logger.warning("Dummy server running"); await asyncio.sleep(3600)
    websockets = type('obj', (object,), {'serve': dummy_serve})()
    async def actual_handle_peer_connection(*args, **kwargs): logger.warning("Dummy connection handler"); await asyncio.sleep(0.1)
    async def connect_to_peer(*a, **kw): logger.warning("Dummy Connect Call"); await asyncio.sleep(0.1); return False
    async def disconnect_from_peer(*a, **kw): logger.warning("Dummy Disconnect Call"); await asyncio.sleep(0.1); return False
    async def send_message_to_peers(*a, **kw): logger.warning("Dummy Send Message Call"); await asyncio.sleep(0.1); return False
    async def send_file(*a, **kw): logger.warning("Dummy Send File Call"); await asyncio.sleep(0.1); return False
    async def send_group_create_message(*a, **kw): logger.warning("Dummy Create Group"); await asyncio.sleep(0.1)
    async def send_group_invite_response(*a, **kw): logger.warning("Dummy Invite Response"); await asyncio.sleep(0.1)
    async def send_group_join_response(*a, **kw): logger.warning("Dummy Join Response"); await asyncio.sleep(0.1)
    async def update_transfer_progress(): await asyncio.sleep(3600)
    async def maintain_peer_list(*a, **kw): await asyncio.sleep(3600)
    # --- End Dummy Fallbacks --- #


# --- Worker and Signals --- #
class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)

class Worker(QRunnable):
    """Executes a function in a separate thread using QThreadPool."""
    def __init__(self, fn, *args, **kwargs): # *** CORRECTED __init__ ***
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.is_async = asyncio.iscoroutinefunction(fn)

    @pyqtSlot()
    def run(self):
        loop = self.kwargs.pop('loop', None)
        try:
            if self.is_async:
                if not callable(self.fn): raise TypeError(f"Target function {self.fn} is not callable.")
                if loop and loop.is_running():
                    future = asyncio.run_coroutine_threadsafe(self.fn(*self.args, **self.kwargs), loop)
                    result = future.result(timeout=60)
                else: raise RuntimeError(f"Async function {getattr(self.fn,'__name__','N/A')} called but no running asyncio loop provided.")
            else: result = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            logger.error(f"Error in worker running {getattr(self.fn, '__name__', str(self.fn))}: {e}", exc_info=True)
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else: self.signals.result.emit(result)
        finally: self.signals.finished.emit()


# --- Custom Events for Thread-Safe Signal Emission --- #
class PeerUpdateEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 1)
    def __init__(self, peers_dict): # *** CORRECTED __init__ ***
        super().__init__(PeerUpdateEvent.TypeId)
        self.peers = peers_dict

class TransferUpdateEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 2)
    def __init__(self, transfers_dict): # *** CORRECTED __init__ ***
        super().__init__(TransferUpdateEvent.TypeId)
        self.transfers = transfers_dict

class GroupUpdateEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 3)
    def __init__(self, groups_dict): # *** CORRECTED __init__ ***
        super().__init__(GroupUpdateEvent.TypeId)
        self.groups = groups_dict

class InviteUpdateEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 4)
    def __init__(self, invites_list): # *** CORRECTED __init__ ***
        super().__init__(InviteUpdateEvent.TypeId)
        self.invites = invites_list

class JoinRequestUpdateEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 5)
    def __init__(self, requests_dict): # *** CORRECTED __init__ ***
        super().__init__(JoinRequestUpdateEvent.TypeId)
        self.requests = requests_dict

class LogMessageEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 6)
    def __init__(self, msg): # *** CORRECTED __init__ ***
        super().__init__(LogMessageEvent.TypeId)
        self.message = msg

class ConnectionRequestEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 7)
    def __init__(self, name, base): # *** CORRECTED __init__ ***
        super().__init__(ConnectionRequestEvent.TypeId)
        self.req_display_name = name
        self.base_username = base

class MessageReceivedEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 8)
    def __init__(self, sender, content): # *** CORRECTED __init__ ***
        super().__init__(MessageReceivedEvent.TypeId)
        self.sender = sender
        self.content = content

class TransferProgressEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 9)
    def __init__(self, tid, prog): # *** CORRECTED __init__ ***
        super().__init__(TransferProgressEvent.TypeId)
        self.transfer_id = tid
        self.progress = prog

class ConnectionStatusEvent(QEvent):
    TypeId = QEvent.Type(QEvent.Type.User + 10)
    def __init__(self, ip, status): # *** CORRECTED __init__ ***
        super().__init__(ConnectionStatusEvent.TypeId)
        self.peer_ip = ip
        self.is_connected = status
# --- End Custom Events --- #


# --- Backend Logic Controller --- #
class Backend(QObject):
    # Signals
    message_received_signal = pyqtSignal(str, str); log_message_signal = pyqtSignal(str)
    peer_list_updated_signal = pyqtSignal(dict); transfers_updated_signal = pyqtSignal(dict)
    connection_status_signal = pyqtSignal(str, bool); connection_request_signal = pyqtSignal(str, str)
    transfer_progress_signal = pyqtSignal(str, int); groups_updated_signal = pyqtSignal(dict)
    invites_updated_signal = pyqtSignal(list); join_requests_updated_signal = pyqtSignal(dict)
    stopped_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.discovery = None; self.loop = None; self.networking_tasks_futures = []; self.networking_tasks = []
        self.websocket_server = None; self.selected_file = None; self._is_running = False

    def set_loop(self, loop): self.loop = loop

    async def _start_async_components(self):
        if not NETWORKING_AVAILABLE:
            logger.warning("Skipping async component start in dummy mode.")
            self.log_message_signal.emit("Running in dummy mode. Network features disabled.")
            return
        logger.info("Backend: Starting async components...")
        try:
            self.discovery = PeerDiscovery()
            self.websocket_server = await websockets.serve(actual_handle_peer_connection, "0.0.0.0", 8765, ping_interval=None, max_size=10 * 1024 * 1024)
            addr = self.websocket_server.sockets[0].getsockname() if self.websocket_server.sockets else "N/A"; logger.info(f"WebSocket server started on {addr}")
            tasks_to_create = [self._process_message_queue(), self.discovery.send_broadcasts(), self.discovery.receive_broadcasts(), self.discovery.cleanup_stale_peers(), update_transfer_progress(), maintain_peer_list(self.discovery)]
            def create_named_task(coro, name): return asyncio.create_task(coro, name=name)
            self.networking_tasks = [create_named_task(coro, name) for coro, name in zip(tasks_to_create, ["MsgQueueProcessor", "DiscoverySend", "DiscoveryRecv", "DiscoveryCleanup", "TransferProgress", "MaintainPeers"])]
            logger.info("Backend: Core networking tasks created."); self.log_message_signal.emit("Network backend started."); self._is_running = True
            self.emit_peer_list_update(); self.emit_transfers_update(); self.emit_groups_update(); self.emit_invites_update(); self.emit_join_requests_update()
            await shutdown_event.wait()
        except OSError as e: logger.critical(f"NETWORK BIND ERROR: {e}", exc_info=True); self.log_message_signal.emit(f"FATAL: Could not start server port 8765. In use? ({e})"); self._is_running = False; shutdown_event.set()
        except Exception as e: logger.exception("Fatal error during async component startup"); self.log_message_signal.emit(f"Network error: {e}"); self._is_running = False; shutdown_event.set()
        finally:
            logger.info("Backend: _start_async_components finished or errored.")
            if self.websocket_server: self.websocket_server.close(); await self.websocket_server.wait_closed(); logger.info("WebSocket server stopped."); self.websocket_server = None

    def start(self):
        if self._is_running: logger.warning("Backend start called while already running."); return
        if self.loop and self.loop.is_running():
             logger.info("Backend: Scheduling async component startup...")
             future = asyncio.run_coroutine_threadsafe(self._start_async_components(), self.loop)
             self.networking_tasks_futures.append(future)
             future.add_done_callback(self._handle_async_start_done)
        else: logger.error("Backend start: asyncio loop not available/running."); self.log_message_signal.emit("Error: Could not start networking loop.")

    def _handle_async_start_done(self, future):
        try:
            exception = future.exception()
            if exception: logger.error(f"Async component startup failed: {exception}", exc_info=exception); self.log_message_signal.emit(f"Network thread error: {exception}")
            else: logger.info("Async components future completed successfully (likely shutdown).")
        except asyncio.CancelledError: logger.info("Async components future cancelled.")
        except Exception as e: logger.error(f"Error in _handle_async_start_done callback: {e}")

    def stop(self):
        if not self._is_running and not shutdown_event.is_set(): logger.warning("Backend stop called but not running or already stopping."); self.stopped_signal.emit(); return
        logger.info("Backend: Stop sequence initiated."); self.log_message_signal.emit("Shutting down network...")
        self._is_running = False
        if self.loop and not shutdown_event.is_set(): self.loop.call_soon_threadsafe(shutdown_event.set); logger.info("Backend: Shutdown event set via call_soon_threadsafe.")
        elif not self.loop: logger.warning("Backend stop: Loop not available."); shutdown_event.set() # Set anyway
        else: logger.info("Backend: Shutdown event already set.")
        if self.discovery:
            try: self.discovery.stop(); logger.info("PeerDiscovery stopped.")
            except Exception as e: logger.error(f"Error stopping PeerDiscovery: {e}")

    async def _process_message_queue(self):
        logger.debug("Starting message queue processor.")
        while not shutdown_event.is_set():
            try:
                item = await asyncio.wait_for(message_queue.get(), timeout=1.0)
                if item:
                    try:
                        def post_event(event_obj): QCoreApplication.instance().postEvent(self, event_obj)
                        if isinstance(item, str): post_event(LogMessageEvent(item))
                        elif isinstance(item, dict):
                            msg_type = item.get("type")
                            if msg_type == "approval_request": req_disp_name = item.get("requesting_username", "Unk"); peer_ip = item.get("peer_ip"); base_user = req_disp_name.split("(")[0]; post_event(ConnectionRequestEvent(req_disp_name, base_user))
                            elif msg_type == "log": message = item.get("message", ""); logger.log(item.get("level", logging.INFO), f"Q: {message}"); post_event(LogMessageEvent(message))
                            elif msg_type == "message": sender = item.get("sender_display_name", "Unk"); content = item.get("content", ""); post_event(MessageReceivedEvent(sender, content))
                            elif msg_type == "transfer_update": self.emit_transfers_update()
                            elif msg_type == "transfer_progress": t_id = item.get("transfer_id"); progress = item.get("progress"); post_event(TransferProgressEvent(t_id, int(progress)))
                            elif msg_type == "peer_update": self.emit_peer_list_update()
                            elif msg_type == "connection_status": peer_ip = item.get("peer_ip"); status = item.get("connected", False); post_event(ConnectionStatusEvent(peer_ip, status)); self.emit_peer_list_update()
                            elif msg_type == "group_list_update": self.emit_groups_update()
                            elif msg_type == "pending_invites_update": self.emit_invites_update()
                            elif msg_type == "join_requests_update": self.emit_join_requests_update()
                            else: logger.warning(f"Unknown message type in queue: {msg_type} - {item}"); post_event(LogMessageEvent(str(item)))
                    except Exception as e: logger.exception(f"Error processing item from message_queue: {item}")
                    finally:
                         if hasattr(message_queue, 'task_done'): message_queue.task_done()
            except asyncio.TimeoutError: continue
            except Exception as e: logger.exception(f"Error in message queue processor loop: {e}"); await asyncio.sleep(1)
        logger.info("Message queue processor stopped.")

    def emit_peer_list_update(self):
         if not self.loop: return
         def get_peers_sync():
             peers = {}; own_ip = getattr(self.discovery, 'own_ip', None) if NETWORKING_AVAILABLE and self.discovery else "127.0.0.1"
             disc_peers = getattr(self.discovery, 'peer_list', {}) if NETWORKING_AVAILABLE and self.discovery else {}
             conn_peers = connections if NETWORKING_AVAILABLE else {}; usernames = peer_usernames if NETWORKING_AVAILABLE else {}
             for ip, (uname, _) in disc_peers.items(): peers[ip] = (uname, ip in conn_peers)
             for ip in conn_peers:
                 if ip != own_ip and ip not in peers: found_uname = next((u for u, i in usernames.items() if i == ip), "Unknown"); peers[ip] = (found_uname, True)
             return peers
         try: peers_dict = get_peers_sync(); QCoreApplication.instance().postEvent(self, PeerUpdateEvent(peers_dict))
         except Exception as e: logger.error(f"Error emitting peer list update: {e}", exc_info=True)

    def emit_transfers_update(self):
         if not self.loop: return
         def get_transfers_sync():
            transfers_info = {}; transfers = active_transfers if NETWORKING_AVAILABLE else {}
            for tid, t in list(transfers.items()):
                try:
                    state_val = getattr(getattr(t, 'state', None), 'value', 'Unknown'); total_s = getattr(t, 'total_size', 0); trans_s = getattr(t, 'transferred_size', 0)
                    prog = int((trans_s / total_s) * 100) if total_s > 0 else 0
                    transfers_info[tid] = {"id": tid, "file_path": getattr(t, 'file_path', 'N/A'), "peer_ip": getattr(t, 'peer_ip', 'N/A'), "direction": getattr(t, 'direction', 'N/A'), "state": state_val, "total_size": total_s, "transferred_size": trans_s, "progress": prog}
                except Exception as e: logger.error(f"Error accessing transfer {tid}: {e}", exc_info=True)
            return transfers_info
         try: transfers_dict = get_transfers_sync(); QCoreApplication.instance().postEvent(self, TransferUpdateEvent(transfers_dict))
         except Exception as e: logger.error(f"Error emitting transfers update: {e}", exc_info=True)

    def emit_groups_update(self):
        if not self.loop: return
        def get_groups_sync(): return groups.copy() if NETWORKING_AVAILABLE else {}
        try: groups_dict = get_groups_sync(); QCoreApplication.instance().postEvent(self, GroupUpdateEvent(groups_dict))
        except Exception as e: logger.error(f"Error emitting groups update: {e}", exc_info=True)

    def emit_invites_update(self):
        if not self.loop: return
        def get_invites_sync(): return list(pending_invites) if NETWORKING_AVAILABLE else []
        try: invites_list = get_invites_sync(); QCoreApplication.instance().postEvent(self, InviteUpdateEvent(invites_list))
        except Exception as e: logger.error(f"Error emitting invites update: {e}", exc_info=True)

    def emit_join_requests_update(self):
        if not self.loop: return
        def get_requests_sync(): return {gn: list(reqs) for gn, reqs in pending_join_requests.items()} if NETWORKING_AVAILABLE else {}
        try: requests_dict = get_requests_sync(); QCoreApplication.instance().postEvent(self, JoinRequestUpdateEvent(requests_dict))
        except Exception as e: logger.error(f"Error emitting join requests update: {e}", exc_info=True)

    def _trigger_async_task(self, coro_func, *args, success_msg=None, error_msg_prefix="Error"):
        if self.loop and self.loop.is_running() and NETWORKING_AVAILABLE:
            logger.info(f"Scheduling task: {coro_func.__name__} with args: {args}")
            worker = Worker(coro_func, *args, loop=self.loop)
            def on_error(err): self.log_message_signal.emit(f"{error_msg_prefix}: {err[1]}")
            def on_finished():
                # We might need to trigger a state refresh after actions complete
                self.emit_peer_list_update(); self.emit_groups_update() # Example refresh
                if success_msg: self.log_message_signal.emit(success_msg)
            worker.signals.error.connect(on_error); worker.signals.finished.connect(on_finished)
            QThreadPool.globalInstance().start(worker); return True
        else: err = "Network unavailable or loop not running."; logger.error(f"Cannot schedule {coro_func.__name__}: {err}"); self.log_message_signal.emit(f"Cannot perform action: {err}"); return False

    def trigger_connect_to_peer(self, peer_ip, requesting_username, target_username): return self._trigger_async_task(connect_to_peer, peer_ip, requesting_username, target_username, error_msg_prefix="Connect Error")
    def trigger_disconnect_from_peer(self, peer_ip): return self._trigger_async_task(disconnect_from_peer, peer_ip, error_msg_prefix="Disconnect Error")
    def trigger_send_message(self, message, target_peer_ip=None): return self._trigger_async_task(send_message_to_peers, message, target_peer_ip, error_msg_prefix="Send Error")
    def trigger_send_file(self, file_path, peers_dict): return self._trigger_async_task(send_file, file_path, peers_dict, error_msg_prefix="Send File Error")
    def trigger_create_group(self, groupname): return self._trigger_async_task(send_group_create_message, groupname, error_msg_prefix="Create Group Error")
    def trigger_accept_invite(self, groupname, inviter_ip): return self._trigger_async_task(send_group_invite_response, groupname, inviter_ip, True, error_msg_prefix="Accept Invite Error")
    def trigger_decline_invite(self, groupname, inviter_ip): return self._trigger_async_task(send_group_invite_response, groupname, inviter_ip, False, error_msg_prefix="Decline Invite Error")
    def trigger_approve_join(self, groupname, requester_ip): return self._trigger_async_task(send_group_join_response, groupname, requester_ip, True, error_msg_prefix="Approve Join Error")
    def trigger_deny_join(self, groupname, requester_ip): return self._trigger_async_task(send_group_join_response, groupname, requester_ip, False, error_msg_prefix="Deny Join Error")

    def choose_file(self, parent_widget=None):
        if QThread.currentThread() != QCoreApplication.instance().thread(): logger.error("choose_file called from wrong thread!"); return None
        selected_file, _ = QFileDialog.getOpenFileName(parent_widget, "Choose File");
        if selected_file: logger.info(f"File selected: {selected_file}"); self.selected_file = selected_file; return selected_file
        else: logger.info("No File Selected"); self.selected_file = None; return None

    def approve_connection(self, peer_ip, requesting_username):
         if self.loop and self.loop.is_running() and NETWORKING_AVAILABLE:
             approval_key = (peer_ip, requesting_username)
             future = pending_approvals.get(approval_key)
             if future and not future.done(): self.loop.call_soon_threadsafe(future.set_result, True); logger.info(f"Conn approved for {requesting_username}"); return True
             else: logger.warning(f"Could not approve conn for {requesting_username}: No pending req {approval_key}."); return False
         return False

    def deny_connection(self, peer_ip, requesting_username):
         if self.loop and self.loop.is_running() and NETWORKING_AVAILABLE:
             approval_key = (peer_ip, requesting_username)
             future = pending_approvals.get(approval_key)
             if future and not future.done(): self.loop.call_soon_threadsafe(future.set_result, False); logger.info(f"Conn denied for {requesting_username}"); return True
             else: logger.warning(f"Could not deny conn for {requesting_username}: No pending req {approval_key}."); return False
         return False

    def event(self, event):
        event_type = event.type()
        if event_type == PeerUpdateEvent.TypeId: self.peer_list_updated_signal.emit(event.peers); return True
        elif event_type == TransferUpdateEvent.TypeId: self.transfers_updated_signal.emit(event.transfers); return True
        elif event_type == GroupUpdateEvent.TypeId: self.groups_updated_signal.emit(event.groups); return True
        elif event_type == InviteUpdateEvent.TypeId: self.invites_updated_signal.emit(event.invites); return True
        elif event_type == JoinRequestUpdateEvent.TypeId: self.join_requests_updated_signal.emit(event.requests); return True
        elif event_type == LogMessageEvent.TypeId: self.log_message_signal.emit(event.message); return True
        elif event_type == ConnectionRequestEvent.TypeId: self.connection_request_signal.emit(event.req_display_name, event.base_username); return True
        elif event_type == MessageReceivedEvent.TypeId: self.message_received_signal.emit(event.sender, event.content); return True
        elif event_type == TransferProgressEvent.TypeId: self.transfer_progress_signal.emit(event.transfer_id, event.progress); return True
        elif event_type == ConnectionStatusEvent.TypeId: self.connection_status_signal.emit(event.peer_ip, event.is_connected); return True
        return super().event(event)


# --- Networking Thread --- #
# --- Networking Thread --- #
class NetworkingThread(QThread):
    """Manages the asyncio event loop."""
    loop_ready = pyqtSignal(object)
    thread_finished = pyqtSignal() # Important for clean shutdown signalling

    def __init__(self, backend_ref):
        super().__init__()
        self.backend = backend_ref
        self.loop = None

    def run(self):
        logger.info("NetworkingThread: Starting...")
        # Set thread names for easier debugging
        thread_name = f"AsyncioLoop-{threading.get_ident()}" # Use Python thread ID
        # self.thread().setObjectName(thread_name) # Naming QThread doesn't always show up well
        threading.current_thread().name = thread_name # Name the Python thread

        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.backend.set_loop(self.loop)
            # Don't emit loop_ready yet

            # Initialize user config first *synchronously within the loop's context*
            if NETWORKING_AVAILABLE:
                 try:
                      logger.info("NetworkingThread: Initializing user config...")
                      self.loop.run_until_complete(initialize_user_config())
                      logger.info("NetworkingThread: User config initialized.")
                      # --- Schedule backend start *within* the loop --- # <--- CHANGE HERE
                      logger.info("NetworkingThread: Scheduling backend start...")
                      # Use create_task as the loop is set for this thread context
                      self.loop.create_task(self.backend._start_async_components(), name="BackendStart")
                      # --- /Schedule --- #
                 except Exception as init_err:
                      logger.exception("NetworkingThread: Failed to initialize user config.")
                      # Use thread-safe signal emission via QCoreApplication event posting
                      QCoreApplication.instance().postEvent(self.backend, LogMessageEvent(f"Config Error: {init_err}"))
                      # Stop thread if config fails
                      raise init_err
            elif not NETWORKING_AVAILABLE: # Dummy mode init
                 self.loop.run_until_complete(initialize_user_config()) # Run dummy init
                 # Schedule dummy backend start if needed, or just let it idle
                 # self.loop.create_task(self.backend._start_async_components(), name="BackendStart") # Optional dummy start

            # Emit loop_ready signal AFTER scheduling backend start
            self.loop_ready.emit(self.loop) # <-- MOVED HERE

            logger.info("NetworkingThread: Starting event loop (run_forever)...")
            self.loop.run_forever()
            # --- run_forever has exited ---
            logger.info("NetworkingThread: run_forever has exited.")

        except Exception as e:
             logger.exception(f"NetworkingThread Error in run(): {e}")
             # Optionally signal GUI about fatal thread error
             QCoreApplication.instance().postEvent(self.backend, LogMessageEvent(f"FATAL Network Thread Error: {e}"))
        finally:
            logger.info("NetworkingThread: Entering finally block...")
            # --- Graceful Loop Shutdown ---
            if self.loop and (self.loop.is_running() or not self.loop.is_closed()):
                 logger.info("NetworkingThread: Running shutdown_tasks...")
                 try:
                     self.loop.run_until_complete(self.shutdown_tasks())
                 except RuntimeError as re: logger.warning(f"NT: Error running shutdown_tasks: {re}")
                 except Exception as sd_err: logger.exception(f"NT: Unexpected error during shutdown_tasks: {sd_err}")

            # --- Close Loop ---
            if self.loop and not self.loop.is_closed():
                 logger.info("NetworkingThread: Closing loop...")
                 self.loop.close()
                 logger.info("NetworkingThread: Loop closed.")
            else: logger.info("NetworkingThread: Loop already closed or None.")

            self.loop = None; self.backend.set_loop(None); self.thread_finished.emit(); logger.info("NetworkingThread: Finished run method.")

    async def shutdown_tasks(self):
        """Cancel all running tasks in the loop."""
        if not self.loop: return
        logger.info("NetworkingThread: Cancelling running asyncio tasks...")
        tasks = [t for t in asyncio.all_tasks(loop=self.loop) if t is not asyncio.current_task()]
        if not tasks: logger.info("NetworkingThread: No tasks to cancel."); return
        logger.info(f"NetworkingThread: Cancelling {len(tasks)} tasks."); [task.cancel() for task in tasks if not task.done()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            task_name = tasks[i].get_name() if hasattr(tasks[i],'get_name') else f"Task-{i}"
            if isinstance(result, asyncio.CancelledError): logger.debug(f"Task '{task_name}' cancelled successfully.")
            elif isinstance(result, Exception): logger.error(f"Error during shutdown of task '{task_name}': {result}", exc_info=result)
        logger.info("NetworkingThread: Task cancellation process complete.")

    def request_stop(self):
        """Requests the event loop to stop gracefully."""
        logger.info("NetworkingThread: Stop requested.")
        if self.loop and self.loop.is_running():
             logger.info("NetworkingThread: Scheduling loop stop.")
             self.loop.call_soon_threadsafe(self.loop.stop)
        elif self.loop: logger.warning("NetworkingThread: Stop requested but loop not running.")
        else: logger.warning("NetworkingThread: Stop requested but loop is None.")

# --- Login Window --- #
class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.settings = QSettings("P2PChat", "Login"); self.setWindowTitle("P2P Chat - Login"); self.setGeometry(200, 200, 380, 280); self.setWindowIcon(QIcon.fromTheme("network-transmit-receive"))
        central_widget = QWidget(); self.setCentralWidget(central_widget); layout = QVBoxLayout(central_widget); layout.setSpacing(15); layout.setContentsMargins(25, 25, 25, 25)
        self.apply_styles(); self.username_label = QLabel("Username:"); self.username_input = QLineEdit(); self.username_input.setPlaceholderText("Enter your username"); layout.addWidget(self.username_label); layout.addWidget(self.username_input); self.remember_me_checkbox = QCheckBox("Remember username"); layout.addWidget(self.remember_me_checkbox); button_layout = QHBoxLayout(); button_layout.setSpacing(10); self.login_button = QPushButton("Login / Register"); self.login_button.setObjectName("login_button"); button_layout.addStretch(); button_layout.addWidget(self.login_button); button_layout.addStretch(); layout.addLayout(button_layout); self.error_label = QLabel(""); self.error_label.setObjectName("error_label"); layout.addWidget(self.error_label)
        self.login_button.clicked.connect(self.login_or_register)
        if self.settings.value("remember_me") == "true": self.remember_me_checkbox.setChecked(True); self.username_input.setText(self.settings.value("username", ""))
    def login_or_register(self):
        username = self.username_input.text().strip()
        if username:
            # Set username in user_data *before* MainWindow uses it
            # This is slightly problematic if user config needs to load first,
            # but essential for Backend triggers to have the username.
            user_data["original_username"] = username
            logger.info(f"Set username for backend: {username}")

            if self.remember_me_checkbox.isChecked(): self.settings.setValue("remember_me", "true"); self.settings.setValue("username", username)
            else: self.settings.setValue("remember_me", "false"); self.settings.remove("username")
            self.error_label.setText(""); self.main_window = MainWindow(username); self.main_window.show(); self.close()
        else: self.error_label.setText("Username cannot be empty."); self.username_input.setFocus()
    def apply_styles(self):
        dark_bg="#1e1e1e"; medium_bg="#252526"; light_bg="#2d2d2d"; dark_border="#333333"; medium_border="#444444"; text_color="#e0e0e0"; dim_text_color="#a0a0a0"; accent_color="#ff6600"; accent_hover="#e65c00"; accent_pressed="#cc5200"; font_family = "Segoe UI, Arial, sans-serif"
        self.setStyleSheet(f"""QMainWindow {{ background-color: {dark_bg}; color: {text_color}; font-family: {font_family}; }} QWidget {{ color: {text_color}; font-size: 13px; }} QLabel {{ font-size: 14px; padding-bottom: 5px; }} QLineEdit {{ background-color: {light_bg}; border: 1px solid {dark_border}; border-radius: 5px; padding: 10px; font-size: 14px; color: {text_color}; }} QLineEdit:focus {{ border: 1px solid {accent_color}; }} QCheckBox {{ font-size: 12px; color: {dim_text_color}; padding-top: 5px; }} QCheckBox::indicator {{ width: 16px; height: 16px; }} QCheckBox::indicator:unchecked {{ border: 1px solid {medium_border}; background-color: {light_bg}; border-radius: 3px; }} QCheckBox::indicator:checked {{ background-color: {accent_color}; border: 1px solid {accent_hover}; border-radius: 3px; }} QPushButton#login_button {{ background-color: {accent_color}; color: white; border: none; border-radius: 5px; padding: 10px 25px; font-size: 14px; font-weight: bold; min-width: 120px; }} QPushButton#login_button:hover {{ background-color: {accent_hover}; }} QPushButton#login_button:pressed {{ background-color: {accent_pressed}; }} QLabel#error_label {{ color: #FFAAAA; font-size: 12px; padding-top: 10px; font-weight: bold; qproperty-alignment: 'AlignCenter'; }}""")


# --- MainWindow --- #
class MainWindow(QMainWindow):
    def __init__(self, username):
        super().__init__(); self.username = username; self.current_chat_peer_username = None; self.chat_widgets = {}; self.chat_histories = defaultdict(list); logger.info("MainWindow: Initializing Backend and NetworkingThread..."); self.backend = Backend(); self.network_thread = NetworkingThread(self.backend); logger.info("MainWindow: Backend and NetworkingThread initialized.")
        # Username already set in LoginWindow
        own_display_name = get_own_display_name() if NETWORKING_AVAILABLE else f"{self.username}(dummy)"; self.setWindowTitle(f"P2P Chat - {own_display_name}"); self.setGeometry(100, 100, 1100, 800); self.selected_file = None
        self.transfer_progress_cache = {} 
        self.central_widget = QWidget(); self.setCentralWidget(self.central_widget); main_layout = QVBoxLayout(self.central_widget); main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)
        self.tab_widget = QTabWidget(); self.chat_tab = QWidget(); self.transfers_tab = QWidget(); self.peers_tab = QWidget(); self.groups_tab = QWidget()
        self.tab_widget.addTab(self.chat_tab, "Chat"); self.tab_widget.addTab(self.transfers_tab, "Transfers"); self.tab_widget.addTab(self.peers_tab, "Network Peers"); self.tab_widget.addTab(self.groups_tab, "Groups")
        main_layout.addWidget(self.tab_widget)
        self.setup_chat_tab(); self.setup_transfers_tab(); self.setup_peers_tab(); self.setup_groups_tab(); self.apply_styles(); self.setup_menu_bar(); self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar); self.status_bar.showMessage("Initializing...")
        self.backend.log_message_signal.connect(self.update_status_bar); self.backend.peer_list_updated_signal.connect(self.update_peer_list_display); self.backend.transfers_updated_signal.connect(self.update_transfer_list_display); self.backend.message_received_signal.connect(self.display_received_message); self.backend.connection_status_signal.connect(self.handle_connection_status_update); self.backend.connection_request_signal.connect(self.show_connection_request); self.backend.transfer_progress_signal.connect(self.update_transfer_progress_display); self.backend.groups_updated_signal.connect(self.update_groups_display); self.backend.invites_updated_signal.connect(self.update_invites_display); self.backend.join_requests_updated_signal.connect(self.update_join_requests_display)
        self.network_thread.thread_finished.connect(self.on_network_thread_finished)

    def setup_menu_bar(self):
        self.menu_bar = QMenuBar(); self.file_menu = QMenu("File", self); self.exit_action = self.file_menu.addAction("Exit"); self.menu_bar.addMenu(self.file_menu); self.help_menu = QMenu("Help", self); self.about_action = self.help_menu.addAction("About"); self.menu_bar.addMenu(self.help_menu); self.setMenuBar(self.menu_bar)
        self.exit_action.triggered.connect(self.close); self.about_action.triggered.connect(self.show_about_dialog)

    def showEvent(self, event):
        super().showEvent(event); logger.info("MainWindow: showEvent - Starting network..."); self.startNetwork(); own_display_name = get_own_display_name(); self.setWindowTitle(f"P2P Chat - {own_display_name}")

    def closeEvent(self, event: QCloseEvent):
        logger.info("MainWindow: Close event triggered."); self.update_status_bar("Shutting down...")
        # self.ui_update_timer.stop() # Stop timer if used
        self.backend.stop(); self.network_thread.request_stop()
        logger.info("MainWindow: Shutdown requested. Waiting for network thread to finish (accepting close event).")
        event.accept() # Accept immediately to avoid unresponsive window

    def startNetwork(self):
        logger.info("MainWindow: Starting network thread...")
        if not self.network_thread.isRunning(): self.network_thread.start(); self.update_status_bar("Starting network...")
        else: logger.warning("MainWindow: Network thread already running.")

    def on_network_thread_finished(self):
         logger.info("MainWindow: Detected NetworkingThread finished."); self.update_status_bar("Network stopped.")
         # QCoreApplication.instance().quit() # Uncomment to force app close

    def on_backend_stopped(self): logger.info("MainWindow: Backend signalled stopped.") # Might be redundant

    def setup_chat_tab(self):
        layout=QHBoxLayout(self.chat_tab);layout.setContentsMargins(0,0,0,0);layout.setSpacing(0);splitter=QSplitter(Qt.Orientation.Horizontal);layout.addWidget(splitter);self.chat_peer_list=QListWidget();self.chat_peer_list.setObjectName("chat_peer_list");self.chat_peer_list.setFixedWidth(250);self.chat_peer_list.currentItemChanged.connect(self.on_chat_peer_selected);splitter.addWidget(self.chat_peer_list);right_pane_widget=QWidget();right_pane_layout=QVBoxLayout(right_pane_widget);right_pane_layout.setContentsMargins(10,10,10,10);right_pane_layout.setSpacing(10);self.chat_stack=QStackedWidget();right_pane_layout.addWidget(self.chat_stack,1);self.no_chat_selected_widget=QLabel("Select a peer to start chatting.");self.no_chat_selected_widget.setAlignment(Qt.AlignmentFlag.AlignCenter);self.no_chat_selected_widget.setStyleSheet("color: #888;");self.chat_stack.addWidget(self.no_chat_selected_widget);splitter.addWidget(right_pane_widget);splitter.setSizes([250,750]);self.update_chat_peer_list()

    def create_chat_widget(self, peer_username):
        if peer_username in self.chat_widgets:
            # logger.debug(f"Chat widget already exists for {peer_username}") # Optional debug
            return self.chat_widgets[peer_username]['widget']

        logger.info(f"Creating chat widget for {peer_username}")
        try:
            chat_widget = QWidget()
            layout = QVBoxLayout(chat_widget); layout.setContentsMargins(0,0,0,0); layout.setSpacing(10)

            logger.debug(f"Creating history QTextEdit for {peer_username}")
            history = QTextEdit(); history.setReadOnly(True); history.setObjectName(f"chat_history_{peer_username}")
            layout.addWidget(history, 1)

            input_layout = QHBoxLayout(); input_layout.setSpacing(5)
            logger.debug(f"Creating input QLineEdit for {peer_username}")
            msg_input = QLineEdit(); msg_input.setPlaceholderText(f"Message {peer_username}..."); msg_input.setObjectName(f"chat_input_{peer_username}")

            logger.debug(f"Creating send QPushButton for {peer_username}")
            send_btn = QPushButton(); send_btn.setObjectName("chat_send_button"); send_btn.setIcon(QIcon.fromTheme("mail-send", QIcon("./icons/send.png"))); send_btn.setFixedSize(QSize(32,32)); send_btn.setIconSize(QSize(20,20)); send_btn.setToolTip(f"Send message to {peer_username}")

            input_layout.addWidget(msg_input); input_layout.addWidget(send_btn); layout.addLayout(input_layout)

            logger.debug(f"Connecting signals for {peer_username}")
            send_btn.clicked.connect(lambda: self.send_chat_message(peer_username))
            msg_input.returnPressed.connect(lambda: self.send_chat_message(peer_username))

            # Store widget references BEFORE populating history
            self.chat_widgets[peer_username]={'widget':chat_widget,'history':history,'input':msg_input,'send_btn':send_btn}

            # Populate history *after* adding to dict
            logger.debug(f"Populating history for {peer_username}")
            history.clear()
            # Use try-except during history population as well
            try:
                 for msg_sender, msg_content in self.chat_histories.get(peer_username,[]):
                     self._append_message_to_history(history, msg_sender, msg_content)
            except Exception as hist_err:
                 logger.error(f"Error populating history for {peer_username}: {hist_err}")

            logger.info(f"Successfully created chat widget for {peer_username}")
            return chat_widget

        except Exception as e:
             # Log any exception during widget creation
             logger.exception(f"CRITICAL ERROR creating chat widget for {peer_username}: {e}")
             # Remove potentially partially created entry if error occurred
             if peer_username in self.chat_widgets:
                 del self.chat_widgets[peer_username]
             return None # Indicate failure
    def on_chat_peer_selected(self, current, previous):
        if current:
            peer_username = current.data(Qt.ItemDataRole.UserRole)
            # Ensure peer_username is valid before proceeding
            if not peer_username:
                logger.error("Selected chat item has invalid data.")
                self.current_chat_peer_username = None
                self.chat_stack.setCurrentWidget(self.no_chat_selected_widget)
                return

            self.current_chat_peer_username = peer_username
            logger.info(f"Chat peer selected: {peer_username}")

            # Get or create the widget
            widget_to_show = self.create_chat_widget(peer_username) # Creates if needed

            # Add widget to stack *only if* it's not already there
            if widget_to_show and self.chat_stack.indexOf(widget_to_show) < 0:
                self.chat_stack.addWidget(widget_to_show)

            # Set current widget (use placeholder if creation failed)
            if widget_to_show:
                 self.chat_stack.setCurrentWidget(widget_to_show)
                 # Give focus to the input field when chat is selected
                 if peer_username in self.chat_widgets:
                     self.chat_widgets[peer_username]['input'].setFocus()
            else:
                 logger.error(f"Could not get or create chat widget for {peer_username}")
                 self.chat_stack.setCurrentWidget(self.no_chat_selected_widget)

            # Mark as read (reset bold)
            font = current.font()
            if font.bold():
                 font.setBold(False)
                 current.setFont(font)
        else: # No item selected
            self.current_chat_peer_username = None
            self.chat_stack.setCurrentWidget(self.no_chat_selected_widget)

    def setup_transfers_tab(self):
        layout=QVBoxLayout(self.transfers_tab);layout.setSpacing(10);layout.setContentsMargins(15,15,15,15);transfer_label=QLabel("Active Transfers:");transfer_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 5px;");layout.addWidget(transfer_label);self.transfer_list=QListWidget();self.transfer_list.setObjectName("transfer_list");layout.addWidget(self.transfer_list,1);self.progress_bar=QProgressBar();self.progress_bar.setValue(0);self.progress_bar.setTextVisible(True);layout.addWidget(self.progress_bar);button_layout=QHBoxLayout();button_layout.setSpacing(10);button_layout.addStretch();self.pause_button=QPushButton("Pause");self.pause_button.setObjectName("pause_button");self.pause_button.setIcon(QIcon.fromTheme("media-playback-pause",QIcon("./icons/pause.png")));self.resume_button=QPushButton("Resume");self.resume_button.setObjectName("resume_button");self.resume_button.setIcon(QIcon.fromTheme("media-playback-start",QIcon("./icons/resume.png")));button_layout.addWidget(self.pause_button);button_layout.addWidget(self.resume_button);layout.addLayout(button_layout);self.transfer_list.currentItemChanged.connect(self.on_transfer_selection_changed);self.pause_button.clicked.connect(self.pause_transfer);self.resume_button.clicked.connect(self.resume_transfer);self.update_transfer_list_display({})

    def setup_peers_tab(self):
        layout=QVBoxLayout(self.peers_tab);layout.setSpacing(15);layout.setContentsMargins(15,15,15,15);peer_label=QLabel("Discovered Network Peers:");peer_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 5px;");layout.addWidget(peer_label);self.network_peer_list=QListWidget();self.network_peer_list.setObjectName("network_peer_list");layout.addWidget(self.network_peer_list,1);conn_button_layout=QHBoxLayout();conn_button_layout.setSpacing(10);conn_button_layout.addStretch();self.connect_button=QPushButton("Connect");self.connect_button.setObjectName("connect_button");self.connect_button.setIcon(QIcon.fromTheme("network-connect",QIcon("./icons/connect.png")));self.disconnect_button=QPushButton("Disconnect");self.disconnect_button.setObjectName("disconnect_button");self.disconnect_button.setIcon(QIcon.fromTheme("network-disconnect",QIcon("./icons/disconnect.png")));conn_button_layout.addWidget(self.connect_button);conn_button_layout.addWidget(self.disconnect_button);layout.addLayout(conn_button_layout);separator=QFrame();separator.setFrameShape(QFrame.Shape.HLine);separator.setFrameShadow(QFrame.Shadow.Sunken);separator.setStyleSheet("border-color: #444;");layout.addWidget(separator);layout.addSpacing(10);file_label=QLabel("Send File to Selected Peer:");file_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 5px;");layout.addWidget(file_label);file_layout=QHBoxLayout();file_layout.setSpacing(10);self.selected_file_label=QLabel("No file chosen");self.selected_file_label.setStyleSheet("color: #aaa;");self.choose_file_button=QPushButton("Choose File");self.choose_file_button.setObjectName("choose_file_button");self.choose_file_button.setIcon(QIcon.fromTheme("document-open",QIcon("./icons/open.png")));self.send_file_button=QPushButton("Send File");self.send_file_button.setObjectName("send_file_button");self.send_file_button.setIcon(QIcon.fromTheme("document-send",QIcon("./icons/send_file.png")));file_layout.addWidget(self.selected_file_label,1);file_layout.addWidget(self.choose_file_button);file_layout.addWidget(self.send_file_button);layout.addLayout(file_layout);self.connect_button.setEnabled(False);self.disconnect_button.setEnabled(False);self.send_file_button.setEnabled(False);self.network_peer_list.currentItemChanged.connect(self.on_network_peer_selection_changed);self.connect_button.clicked.connect(self.connect_to_selected_peer);self.disconnect_button.clicked.connect(self.disconnect_from_selected_peer);self.choose_file_button.clicked.connect(self.choose_file_action);self.send_file_button.clicked.connect(self.send_selected_file_action);self.update_peer_list_display({})

    def setup_groups_tab(self):
        main_layout=QHBoxLayout(self.groups_tab);main_layout.setSpacing(10);main_layout.setContentsMargins(15,15,15,15);left_column=QVBoxLayout();left_column.setSpacing(10);main_layout.addLayout(left_column,1);groups_label=QLabel("Your Groups:");groups_label.setStyleSheet("font-weight: bold;");self.groups_list=QListWidget();self.groups_list.setObjectName("groups_list");left_column.addWidget(groups_label);left_column.addWidget(self.groups_list,1);create_gb_layout=QVBoxLayout();create_gb_layout.setSpacing(5);create_label=QLabel("Create New Group:");create_label.setStyleSheet("font-weight: bold;");self.create_group_input=QLineEdit();self.create_group_input.setPlaceholderText("New group name...");self.create_group_button=QPushButton("Create Group");self.create_group_button.setObjectName("create_group_button");create_gb_layout.addWidget(create_label);create_gb_layout.addWidget(self.create_group_input);create_gb_layout.addWidget(self.create_group_button);left_column.addLayout(create_gb_layout);middle_column=QVBoxLayout();middle_column.setSpacing(10);main_layout.addLayout(middle_column,2);self.selected_group_label=QLabel("Selected Group: None");self.selected_group_label.setStyleSheet("font-weight: bold; font-size: 15px;");members_label=QLabel("Members:");members_label.setStyleSheet("font-weight: bold;");self.group_members_list=QListWidget();self.group_members_list.setObjectName("group_members_list");self.admin_section_widget=QWidget();admin_layout=QVBoxLayout(self.admin_section_widget);admin_layout.setContentsMargins(0,5,0,0);admin_layout.setSpacing(5);jr_label=QLabel("Pending Join Requests (Admin Only):");jr_label.setStyleSheet("font-weight: bold;");self.join_requests_list=QListWidget();self.join_requests_list.setObjectName("join_requests_list");jr_button_layout=QHBoxLayout();jr_button_layout.addStretch();self.approve_join_button=QPushButton("Approve Join");self.approve_join_button.setObjectName("approve_join_button");self.deny_join_button=QPushButton("Deny Join");self.deny_join_button.setObjectName("deny_join_button");jr_button_layout.addWidget(self.approve_join_button);jr_button_layout.addWidget(self.deny_join_button);admin_layout.addWidget(jr_label);admin_layout.addWidget(self.join_requests_list,1);admin_layout.addLayout(jr_button_layout);self.admin_section_widget.setVisible(False);middle_column.addWidget(self.selected_group_label);middle_column.addWidget(members_label);middle_column.addWidget(self.group_members_list,1);middle_column.addWidget(self.admin_section_widget);right_column=QVBoxLayout();right_column.setSpacing(10);main_layout.addLayout(right_column,1);invites_label=QLabel("Pending Invitations:");invites_label.setStyleSheet("font-weight: bold;");self.pending_invites_list=QListWidget();self.pending_invites_list.setObjectName("pending_invites_list");invite_button_layout=QHBoxLayout();invite_button_layout.addStretch();self.accept_invite_button=QPushButton("Accept Invite");self.accept_invite_button.setObjectName("accept_invite_button");self.decline_invite_button=QPushButton("Decline Invite");self.decline_invite_button.setObjectName("decline_invite_button");invite_button_layout.addWidget(self.accept_invite_button);invite_button_layout.addWidget(self.decline_invite_button);right_column.addWidget(invites_label);right_column.addWidget(self.pending_invites_list,1);right_column.addLayout(invite_button_layout);self.groups_list.currentItemChanged.connect(self.on_group_selected);self.pending_invites_list.currentItemChanged.connect(self.on_invite_selected);self.join_requests_list.currentItemChanged.connect(self.on_join_request_selected);self.create_group_button.clicked.connect(self.create_group_action);self.accept_invite_button.clicked.connect(self.accept_invite_action);self.decline_invite_button.clicked.connect(self.decline_invite_action);self.approve_join_button.clicked.connect(self.approve_join_action);self.deny_join_button.clicked.connect(self.deny_join_action);self.accept_invite_button.setEnabled(False);self.decline_invite_button.setEnabled(False);self.approve_join_button.setEnabled(False);self.deny_join_button.setEnabled(False);self.update_groups_display({});self.update_invites_display([]);self.update_join_requests_display({})

    # --- Slot Methods for UI Updates ---
    @pyqtSlot(str)
    def update_status_bar(self, message): self.status_bar.showMessage(message, 5000)

    @pyqtSlot(dict)
    def update_peer_list_display(self, peers_status):
        # NOTE: The incoming peers_status is assumed to be from the discovery list now:
        

        logger.debug(f"Updating network peer list display with {len(peers_status)} discovered peers.")
        current_sel_data = self.network_peer_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.network_peer_list.currentItem() else None
        self.network_peer_list.clear(); new_sel_item = None
        own_ip = getattr(self.backend.discovery, 'own_ip', None) if NETWORKING_AVAILABLE and self.backend.discovery else "127.0.0.1"

        # The keys of peers_status are the IPs from discovery.peer_list
        for ip, peer_info in peers_status.items():
            if ip == own_ip: continue # Skip self

            # --- *** MODIFIED LOGIC *** ---
            discovered_username = peer_info[0] # Get username directly from discovery data
            is_connected = ip in connections # Check current connection status

            # Determine display name: Use discovery username, add device ID ONLY if connected
            display_name = discovered_username
            if is_connected:
                # If connected, try getting the potentially more complete display name
                # which might include the device ID suffix if needed.
                display_name = get_peer_display_name(ip) # Use the function for connected peers
            elif not discovered_username: # Handle case where discovery somehow had no username
                 display_name = "Unknown"
            # --- *** END MODIFIED LOGIC *** ---

            status = " (Connected)" if is_connected else " (Discovered)"
            item_text = f"{display_name} [{ip}]{status}"
            item = QListWidgetItem(item_text)
            # Store consistent data for actions
            item_data = {"ip": ip, "username": discovered_username, "connected": is_connected, "display_name": display_name}
            item.setData(Qt.ItemDataRole.UserRole, item_data)
            self.network_peer_list.addItem(item)

            # Reselection logic
            if current_sel_data and current_sel_data.get("ip") == ip:
                new_sel_item = item

        if not peers_status: # Add placeholder if list is empty (after filtering self)
             item = QListWidgetItem("No other peers discovered")
             item.setForeground(QColor("#888"))
             item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
             self.network_peer_list.addItem(item)

        if new_sel_item: self.network_peer_list.setCurrentItem(new_sel_item)
        else: self.on_network_peer_selection_changed(None, None) # Clear selection effects

        # NOTE: We still call update_chat_peer_list here, which correctly
        # only adds currently *connected* peers based on the `connections` dict.
        self.update_chat_peer_list()

    def update_chat_peer_list(self):
        logger.debug("Updating chat peer list."); current_chat_sel = self.chat_peer_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.chat_peer_list.currentItem() else None; self.chat_peer_list.clear(); connected_peer_data = {}
        conn_peers = connections if NETWORKING_AVAILABLE else {"192.168.1.10": object()}
        for ip in conn_peers.keys(): display_name = get_peer_display_name(ip) if NETWORKING_AVAILABLE else f"DummyPeer_{ip}"; base_username = display_name.split("(")[0]; connected_peer_data[base_username] = display_name
        if not connected_peer_data: item = QListWidgetItem("No connected peers"); item.setForeground(QColor("#888")); item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable); self.chat_peer_list.addItem(item)
        else:
            new_sel_item = None
            for username in sorted(connected_peer_data.keys()): display_name = connected_peer_data[username]; item = QListWidgetItem(display_name); item.setData(Qt.ItemDataRole.UserRole, username); self.chat_peer_list.addItem(item)
            if username == current_chat_sel: new_sel_item = item
            if new_sel_item: self.chat_peer_list.setCurrentItem(new_sel_item)
        if self.current_chat_peer_username and self.current_chat_peer_username not in connected_peer_data:
              logger.info(f"Current chat peer '{self.current_chat_peer_username}' disconnected.")
              if self.current_chat_peer_username in self.chat_widgets: self.chat_widgets[self.current_chat_peer_username]['input'].setEnabled(False); self.chat_widgets[self.current_chat_peer_username]['send_btn'].setEnabled(False)
              self.current_chat_peer_username = None; self.chat_stack.setCurrentWidget(self.no_chat_selected_widget)

    @pyqtSlot(dict)
       
    def update_transfer_list_display(self, transfers_info):
        logger.debug(f"Updating transfer list display with {len(transfers_info)} items.")
        current_sel_id = self.transfer_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.transfer_list.currentItem() else None
        self.transfer_list.clear(); new_sel_item = None

        # Keep track of current IDs to clean cache later
        current_transfer_ids = set(transfers_info.keys()) # Define this at the start of the method

        if not transfers_info:
            item = QListWidgetItem("No active transfers"); item.setForeground(QColor("#888")); item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable); self.transfer_list.addItem(item)
        else:
            for tid, t_info in transfers_info.items():
                progress = t_info.get('progress', 0)
                self.transfer_progress_cache[tid] = progress # Update cache

                file_name = os.path.basename(t_info.get('file_path', 'Unk')); state = t_info.get('state', 'Unk'); direction = t_info.get('direction', '??'); peer_ip = t_info.get('peer_ip', '??'); peer_name = get_peer_display_name(peer_ip) if NETWORKING_AVAILABLE else f"P_{peer_ip}"; direction_symbol = "⬆️" if direction == "send" else "⬇️"
                item_text = f"{direction_symbol} {file_name} ({peer_name}) - {state} [{progress}%]" # Use updated progress
                item = QListWidgetItem(item_text); item.setData(Qt.ItemDataRole.UserRole, tid); self.transfer_list.addItem(item)
                if tid == current_sel_id: new_sel_item = item

            if new_sel_item: self.transfer_list.setCurrentItem(new_sel_item)

        # --- Correctly Indented Cache Cleanup ---
        cached_ids = list(self.transfer_progress_cache.keys())
        for tid in cached_ids:
            if tid not in current_transfer_ids:
                # Safely delete from cache
                try:
                    del self.transfer_progress_cache[tid]
                    logger.debug(f"Removed transfer {tid} from progress cache.")
                except KeyError:
                    logger.warning(f"Attempted to remove non-existent key {tid} from progress cache.")

        # --- Correctly Indented Call ---
        # Update buttons/progress bar based on current selection (which might have changed)
        self.on_transfer_selection_changed(self.transfer_list.currentItem(), None)
    

    @pyqtSlot(str, int)
    def update_transfer_progress_display(self, transfer_id, progress):
     """Updates the cache and the progress bar if the item is selected."""
     # Always update the cache with the latest progress
     self.transfer_progress_cache[transfer_id] = progress

     # Update the visible progress bar ONLY if this transfer is selected
     current_item = self.transfer_list.currentItem()
     if current_item and current_item.data(Qt.ItemDataRole.UserRole) == transfer_id:
          self.progress_bar.setValue(progress)

    def _append_message_to_history(self, history_widget, sender, message):
        timestamp = time.strftime("%H:%M:%S"); formatted_message = f'<span style="color:#aaa;">[{timestamp}]</span> <b>{sender}:</b> {message}'; history_widget.append(formatted_message); history_widget.moveCursor(QTextCursor.MoveOperation.End)

    @pyqtSlot(str, str)
        
    def display_received_message(self, sender_display_name, message):
        """Displays a received message in the correct chat window."""
        # Extract base username robustly
        base_sender_username = sender_display_name
        # Handle names potentially missing device ID
        if "(" in sender_display_name and sender_display_name.endswith(")"):
            base_sender_username = sender_display_name[:sender_display_name.rfind("(")]

        logger.debug(f"Attempting to display message from {sender_display_name} (base: {base_sender_username})")

        # Ensure chat widget exists (might receive message before selecting chat)
        self.create_chat_widget(base_sender_username) # Creates if not exists

        # **** Check if widget exists in dict BEFORE accessing ****
        if base_sender_username in self.chat_widgets:
            # Append to persistent history
            self.chat_histories[base_sender_username].append((sender_display_name, message))

            # Append to UI widget
            try:
                # Access widgets safely
                history_widget = self.chat_widgets[base_sender_username]['history']
                self._append_message_to_history(history_widget, sender_display_name, message)
            except KeyError as e:
                 logger.error(f"KeyError accessing chat widget components for {base_sender_username} after creation attempt: {e}")
                 self.update_status_bar(f"UI Error displaying message from {sender_display_name}")
                 return # Stop processing this message if widgets are missing

            # Indicate unread if not the current chat
            if self.current_chat_peer_username != base_sender_username:
                 # Find item using the base username stored in its UserRole data
                 for i in range(self.chat_peer_list.count()):
                      item = self.chat_peer_list.item(i)
                      # Check if item data exists and matches
                      item_data = item.data(Qt.ItemDataRole.UserRole)
                      if item_data == base_sender_username:
                           font = item.font()
                           font.setBold(True)
                           item.setFont(font)
                           break # Found the item
        else:
            # This case indicates create_chat_widget failed to add the entry
            logger.error(f"Chat widget for {base_sender_username} not found in self.chat_widgets after creation attempt.")
            self.update_status_bar(f"UI Error preparing chat for {sender_display_name}")
    @pyqtSlot(str, bool)
    def handle_connection_status_update(self, peer_ip, is_connected):
        logger.info(f"Conn status update: IP={peer_ip}, Connected={is_connected}"); peer_name = get_peer_display_name(peer_ip) if NETWORKING_AVAILABLE else f"P_{peer_ip}"; status_msg = f"{peer_name} has {'connected' if is_connected else 'disconnected'}." ; self.update_status_bar(status_msg)
        # Lists updated via backend emit_* calls triggered by network events

    @pyqtSlot(str, str)
    def show_connection_request(self, requesting_display_name, base_username_for_cmd):
        approval_key = None; pending_peer_ip = None
        if NETWORKING_AVAILABLE:
             for key, future in pending_approvals.items():
                  # Assuming key is (peer_ip, base_username) tuple based on Backend code
                  p_ip, req_user = key
                  if req_user == base_username_for_cmd: approval_key = key; pending_peer_ip = p_ip; break
        if not approval_key or not pending_peer_ip: # Check both
            logger.error(f"No pending approval found for {base_username_for_cmd} or IP missing.");
            self.update_status_bar(f"Error handling request from {requesting_display_name}")
            return

        reply = QMessageBox.question(self, "Conn Req", f"Accept connection from:\n{requesting_display_name}?", QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes: success = self.backend.approve_connection(pending_peer_ip, base_username_for_cmd); self.update_status_bar(f"Approved {requesting_display_name}" if success else f"Failed approval")
        else: success = self.backend.deny_connection(pending_peer_ip, base_username_for_cmd); self.update_status_bar(f"Denied {requesting_display_name}" if success else f"Failed denial")

    @pyqtSlot(dict)
    def update_groups_display(self, groups_data):
         logger.debug(f"Updating groups list display: {len(groups_data)} groups")
         # Get current selection *before* clearing
         current_selection = self.groups_list.currentItem()
         current_sel_groupname = current_selection.data(Qt.ItemDataRole.UserRole) if current_selection else None

         self.groups_list.clear()
         item_to_reselect = None # Store the QListWidgetItem to reselect

         if not groups_data:
            # Handle the case where there are no groups
            item = QListWidgetItem("No groups found.")
            item.setForeground(QColor("#888"))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.groups_list.addItem(item)
            # Ensure details are cleared if no groups exist
            if self.selected_group_label.text() != "Selected Group: None":
                 self.on_group_selected(None, None) # Trigger clearing details
         else:
            # Populate the list with current groups
            for groupname_in_loop in sorted(groups_data.keys()):
                 item = QListWidgetItem(groupname_in_loop)
                 item.setData(Qt.ItemDataRole.UserRole, groupname_in_loop)
                 self.groups_list.addItem(item)
                 # Check if this item was the previously selected one *inside the loop*
                 if groupname_in_loop == current_sel_groupname:
                     item_to_reselect = item # Mark this QListWidgetItem

            # After the loop, attempt to reselect the marked item if found
            if item_to_reselect:
                # Check if it's already selected to avoid unnecessary signal emission if possible
                # However, setCurrentItem might be needed to visually confirm selection after clear()
                self.groups_list.setCurrentItem(item_to_reselect)
                # Re-call the selection handler AFTER setting the current item
                # to ensure the details pane updates correctly based on the re-selected item.
                self.on_group_selected(item_to_reselect, None)

            elif current_sel_groupname is not None:
                # If there was a selection previously, but it wasn't found in the new list
                self.on_group_selected(None, None)
            # else: No previous selection and nothing matched, list populated, details already cleared.
    

    @pyqtSlot(list)
    def update_invites_display(self, invites_list):
        logger.debug(f"Updating invites list: {len(invites_list)} invites"); current_sel_data = self.pending_invites_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.pending_invites_list.currentItem() else None; self.pending_invites_list.clear(); new_sel_item = None
        for invite in invites_list:
            groupname = invite.get("groupname"); inviter_ip = invite.get("inviter_ip"); inviter_name = get_peer_display_name(inviter_ip) if NETWORKING_AVAILABLE else f"P_{inviter_ip}"; item_text = f"{groupname} (from {inviter_name})"
            item = QListWidgetItem(item_text); item_data = {"groupname": groupname, "inviter_ip": inviter_ip}; item.setData(Qt.ItemDataRole.UserRole, item_data); self.pending_invites_list.addItem(item)
            if current_sel_data and current_sel_data == item_data: new_sel_item = item
        if new_sel_item: self.pending_invites_list.setCurrentItem(new_sel_item)
        self.on_invite_selected(self.pending_invites_list.currentItem(), None)

    @pyqtSlot(dict)
    def update_join_requests_display(self, requests_dict):
        logger.debug(f"Updating join requests display"); selected_group_item = self.groups_list.currentItem()
        if not selected_group_item: self.join_requests_list.clear(); return
        selected_groupname = selected_group_item.data(Qt.ItemDataRole.UserRole); requests = requests_dict.get(selected_groupname, []); current_sel_data = self.join_requests_list.currentItem().data(Qt.ItemDataRole.UserRole) if self.join_requests_list.currentItem() else None; self.join_requests_list.clear(); new_sel_item = None
        if self.admin_section_widget.isVisible():
            for req in requests:
                req_ip = req.get("requester_ip"); req_uname = req.get("requester_username", "Unk"); req_display_name = get_peer_display_name(req_ip) if NETWORKING_AVAILABLE else req_uname; item_text = f"{req_display_name} ({req_ip})"
                item = QListWidgetItem(item_text); item_data = {"groupname": selected_groupname, "requester_ip": req_ip, "requester_username": req_uname}; item.setData(Qt.ItemDataRole.UserRole, item_data); self.join_requests_list.addItem(item)
                if current_sel_data and current_sel_data == item_data: new_sel_item = item
            if new_sel_item: self.join_requests_list.setCurrentItem(new_sel_item)
        self.on_join_request_selected(self.join_requests_list.currentItem(), None)

    def on_network_peer_selection_changed(self, current, previous):
        """Enable/disable buttons based on network peer selection and connection status."""
        can_connect = False
        can_disconnect = False
        can_send_file = False
        peer_data = None # Initialize peer_data to None

        if current:
            # Attempt to get data from the current item
            peer_data = current.data(Qt.ItemDataRole.UserRole)

            # Check if data was successfully retrieved and is valid
            if peer_data:
                is_connected = peer_data.get("connected", False)
                can_connect = not is_connected
                can_disconnect = is_connected
                # Check if a file is selected *and* the peer is connected
                can_send_file = is_connected and (self.selected_file is not None)
            else:
                # Handle case where item exists but has no data (shouldn't happen often)
                logger.warning("Selected peer item has no associated data.")

        # Set button states based on the flags determined above
        # If current is None, or peer_data was None, flags remain False
        self.connect_button.setEnabled(can_connect)
        self.disconnect_button.setEnabled(can_disconnect)
        self.send_file_button.setEnabled(can_send_file)
    def on_transfer_selection_changed(self, current, previous):
    
      can_pause = False; can_resume = False; progress = 0
      if current:
        transfer_id = current.data(Qt.ItemDataRole.UserRole)
        # Get state from active_transfers (needed for button state)
        state_value = "Unknown"; transfer_obj = None
        if NETWORKING_AVAILABLE and transfer_id in active_transfers: transfer_obj = active_transfers[transfer_id]
        elif not NETWORKING_AVAILABLE and transfer_id in active_transfers: transfer_obj = active_transfers[transfer_id] # Dummy

        if transfer_obj:
             state_value = getattr(getattr(transfer_obj, 'state', None), 'value', 'Unknown')
             can_pause = state_value == (TransferState.IN_PROGRESS.value if NETWORKING_AVAILABLE else "Sending")
             can_resume = state_value == (TransferState.PAUSED.value if NETWORKING_AVAILABLE else "Paused")

        # *** Get progress from the cache ***
        progress = self.transfer_progress_cache.get(transfer_id, 0) # Default to 0 if not found

      self.pause_button.setEnabled(can_pause)
      self.resume_button.setEnabled(can_resume)
      self.progress_bar.setValue(progress) # Set bar from cache
    # --- Action Methods with Corrected Indentation --- #
    def connect_to_selected_peer(self):
        selected_item = self.network_peer_list.currentItem()
        if selected_item:
            peer_data = selected_item.data(Qt.ItemDataRole.UserRole)
            if not peer_data:
                self.update_status_bar("Error: Invalid peer data.")
                logger.error("Invalid peer data found in connect_to_selected_peer.")
                return
            peer_ip = peer_data.get("ip")
            target_username = peer_data.get("username")
            if not peer_ip or not target_username:
                self.update_status_bar("Error: Peer data incomplete.")
                return
            self.update_status_bar(f"Connecting to {target_username}...")
            requesting_username = user_data.get("original_username", "UnknownUser")
            self.backend.trigger_connect_to_peer(peer_ip, requesting_username, target_username)
        else:
            self.update_status_bar("No peer selected.")

    def disconnect_from_selected_peer(self):
        selected_item = self.network_peer_list.currentItem()
        if selected_item:
            peer_data = selected_item.data(Qt.ItemDataRole.UserRole)
            if not peer_data:
                 self.update_status_bar("Error: Invalid peer data.")
                 logger.error("Invalid peer data found in disconnect_from_selected_peer.")
                 return
            peer_ip = peer_data.get("ip")
            target_display = peer_data.get("username", peer_ip)
            if not peer_ip:
                 self.update_status_bar("Error: Peer IP not found.")
                 return
            self.update_status_bar(f"Disconnecting from {target_display}...")
            self.backend.trigger_disconnect_from_peer(peer_ip)
        else:
             self.update_status_bar("No peer selected.")

        # Inside class MainWindow:
        # --- Add this NEW method inside the MainWindow class ---
    def display_sent_message(self, recipient_username, message):
        """Displays a message sent by the user in the correct chat window."""
        # Get your own display name
        own_name = get_own_display_name() if NETWORKING_AVAILABLE else f"{self.username}(You)"

        # Append to the persistent history cache first
        self.chat_histories[recipient_username].append((own_name, message))

        # Check if the chat widget exists for this recipient
        if recipient_username in self.chat_widgets:
            try:
                history_widget = self.chat_widgets[recipient_username]['history']
                # Append the formatted message to the text edit
                self._append_message_to_history(history_widget, own_name, message)
            except KeyError:
                logger.error(f"KeyError accessing chat widget components for {recipient_username} in display_sent_message.")
            except Exception as e:
                logger.exception(f"Error updating sent message display for {recipient_username}: {e}")
        else:
            # This might happen if a message is sent immediately after connecting
            # before the UI has fully switched, or if create_chat_widget failed.
            logger.warning(f"Attempted to display sent message to '{recipient_username}', but their chat widget was not found in self.chat_widgets.")
            # Optionally, you could try creating the widget here again, but it might indicate another issue.
            # self.create_chat_widget(recipient_username)
            # if recipient_username in self.chat_widgets: ... retry appending ...
    # --- End of NEW method ---

    # --- Ensure send_chat_message calls the correct method ---
    def send_chat_message(self, peer_username):
        if not peer_username or peer_username not in self.chat_widgets:
            logger.error(f"Send invalid chat target: {peer_username}")
            return

        widgets = self.chat_widgets[peer_username]
        message = widgets['input'].text().strip()

        if not message:
            logger.debug("Empty message entered, not sending.")
            return

        # *** Make sure this line calls the method you just defined ***
        self.display_sent_message(peer_username, message) # Call the correct method

        # Find target IP
        target_ip = next((ip for u, ip in peer_usernames.items() if u == peer_username), None) if NETWORKING_AVAILABLE else None
        logger.info(f"Attempting to send to {peer_username}. Found IP: {target_ip}. Message: '{message[:50]}...'")

        if target_ip:
            success = self.backend.trigger_send_message(message, target_peer_ip=target_ip)
            logger.info(f"Backend trigger_send_message returned: {success}")
            if success:
                 widgets['input'].clear()
            else:
                 self.update_status_bar(f"Failed to schedule send for {peer_username}")
        else:
            self.update_status_bar(f"Error: Could not find IP for {peer_username}")
            logger.error(f"Could not find IP for username {peer_username} in peer_usernames: {peer_usernames}")

    # --- Keep _append_message_to_history and other methods ---
    
    def choose_file_action(self):
        path = self.backend.choose_file(self)
        if path: self.selected_file = path; self.selected_file_label.setText(os.path.basename(path)); self.selected_file_label.setStyleSheet("color: #e0e0e0;"); self.update_status_bar(f"File chosen: {os.path.basename(path)}")
        else: self.selected_file = None; self.selected_file_label.setText("No file chosen"); self.selected_file_label.setStyleSheet("color: #aaa;"); self.update_status_bar("File selection cancelled.")
        self.on_network_peer_selection_changed(self.network_peer_list.currentItem(), None) # Update send button

    def send_selected_file_action(self):
        selected_item = self.network_peer_list.currentItem()
        if not self.selected_file: self.update_status_bar("No file chosen."); return
        if not selected_item: self.update_status_bar("No peer selected."); return
        data = selected_item.data(Qt.ItemDataRole.UserRole); ip = data.get("ip"); uname = data.get("username", ip)
        if not ip: self.update_status_bar(f"Cannot send: IP not found for {uname}."); return
        if not data.get("connected", False): self.update_status_bar(f"Cannot send: Not connected to {uname}."); return
        ws = connections.get(ip) if NETWORKING_AVAILABLE else object()
        if not ws and NETWORKING_AVAILABLE: self.update_status_bar(f"Cannot send: Conn object missing for {uname}."); logger.error(f"Conn obj missing for {ip}"); return
        peers_dict = {ip: ws}; fname = os.path.basename(self.selected_file); self.update_status_bar(f"Initiating send {fname} to {uname}...")
        self.backend.trigger_send_file(self.selected_file, peers_dict)

    def pause_transfer(self): logger.warning("Pause transfer action not implemented yet.") # TODO
    def resume_transfer(self): logger.warning("Resume transfer action not implemented yet.") # TODO

    def on_group_selected(self, current, previous):
        self.group_members_list.clear(); self.join_requests_list.clear(); self.admin_section_widget.setVisible(False); self.approve_join_button.setEnabled(False); self.deny_join_button.setEnabled(False)
        if current:
            groupname = current.data(Qt.ItemDataRole.UserRole); self.selected_group_label.setText(f"Group: {groupname}")
            info = groups.get(groupname) if NETWORKING_AVAILABLE else None
            if info:
                [self.group_members_list.addItem(f"{get_peer_display_name(m)} ({m})") for m in sorted(list(info.get("members", set())))]
                own_ip = getattr(self.backend.discovery, 'own_ip', None) if NETWORKING_AVAILABLE and self.backend.discovery else None
                if own_ip and own_ip == info.get("admin"): self.admin_section_widget.setVisible(True); self.backend.emit_join_requests_update()
                else: self.admin_section_widget.setVisible(False)
            else: logger.warning(f"No group info for {groupname}")
        else: self.selected_group_label.setText("Selected Group: None")

    def on_invite_selected(self, current, previous): self.accept_invite_button.setEnabled(current is not None); self.decline_invite_button.setEnabled(current is not None)
    def on_join_request_selected(self, current, previous): self.approve_join_button.setEnabled(current is not None); self.deny_join_button.setEnabled(current is not None)

    def create_group_action(self):
        name = self.create_group_input.text().strip()
        if not name: self.update_status_bar("Enter group name."); self.create_group_input.setFocus(); return
        if NETWORKING_AVAILABLE and name in groups: self.update_status_bar(f"Group '{name}' exists."); return
        self.update_status_bar(f"Creating group '{name}'...")
        if self.backend.trigger_create_group(name): self.create_group_input.clear()
        else: self.update_status_bar(f"Failed initiation.")

    def accept_invite_action(self):
        item = self.pending_invites_list.currentItem()
        if item:
            data = item.data(Qt.ItemDataRole.UserRole); gn = data.get("groupname"); ip = data.get("inviter_ip");
            if gn and ip: self.update_status_bar(f"Accepting '{gn}'..."); self.backend.trigger_accept_invite(gn, ip)
            else: self.update_status_bar("Invalid invite data.")
        else: self.update_status_bar("No invite selected.")

    def decline_invite_action(self):
        item = self.pending_invites_list.currentItem()
        if item:
            data = item.data(Qt.ItemDataRole.UserRole); gn = data.get("groupname"); ip = data.get("inviter_ip");
            if gn and ip: self.update_status_bar(f"Declining '{gn}'..."); self.backend.trigger_decline_invite(gn, ip)
            else: self.update_status_bar("Invalid invite data.")
        else: self.update_status_bar("No invite selected.")

    def approve_join_action(self):
         item = self.join_requests_list.currentItem()
         if item:
             data = item.data(Qt.ItemDataRole.UserRole); gn = data.get("groupname"); ip = data.get("requester_ip"); un = data.get("requester_username", "Unk");
             if gn and ip: self.update_status_bar(f"Approving {un} for '{gn}'..."); self.backend.trigger_approve_join(gn, ip)
             else: self.update_status_bar("Invalid join request data.")
         else: self.update_status_bar("No join request selected.")

    def deny_join_action(self):
         item = self.join_requests_list.currentItem()
         if item:
             data = item.data(Qt.ItemDataRole.UserRole); gn = data.get("groupname"); ip = data.get("requester_ip"); un = data.get("requester_username", "Unk");
             if gn and ip: self.update_status_bar(f"Denying {un} for '{gn}'..."); self.backend.trigger_deny_join(gn, ip)
             else: self.update_status_bar("Invalid join request data.")
         else: self.update_status_bar("No join request selected.")

    def show_about_dialog(self):
        own = get_own_display_name() if NETWORKING_AVAILABLE else self.username; QMessageBox.about(self, "About P2P Chat", f"P2P Chat App v0.3\nUser: {own}\n\nPyQt6 + Asyncio")

    def apply_styles(self):
        font_family="Segoe UI, Arial, sans-serif";dark_bg="#1e1e1e";medium_bg="#252526";light_bg="#2d2d2d";dark_border="#333333";medium_border="#444444";text_color="#e0e0e0";dim_text_color="#a0a0a0";accent_color="#ff6600";accent_hover="#e65c00";accent_pressed="#cc5200";secondary_btn_bg="#555555";secondary_btn_hover="#666666";secondary_btn_pressed="#444444"
        stylesheet_template="""QMainWindow{{background-color:{dark_bg};color:{text_color};font-family:{font_family};}}QWidget{{color:{text_color};font-size:13px;}}QTabWidget::pane{{border:none;background-color:{medium_bg};}}QTabBar::tab{{background:{dark_border};color:{dim_text_color};border:none;padding:10px 20px;font-size:14px;font-weight:bold;margin-right:2px;border-top-left-radius:5px;border-top-right-radius:5px;}}QTabBar::tab:selected{{background:{accent_color};color:#000000;}}QTabBar::tab:!selected{{margin-top:2px;padding:8px 20px;background:#3a3a3a;}}QTabBar::tab:!selected:hover{{background:{medium_border};color:{text_color};}}QListWidget{{background-color:{medium_bg};border:1px solid {dark_border};border-radius:5px;padding:5px;font-size:14px;outline:none;}}QListWidget::item{{padding:7px 5px;border-radius:3px;}}QListWidget::item:selected{{background-color:{accent_color};color:#000000;font-weight:bold;}}QListWidget::item:!selected:hover{{background-color:{medium_border};}}QListWidget#chat_peer_list{{border-right:2px solid {dark_border};}}QTextEdit[objectName^="chat_history"]{{background-color:{medium_bg};border:none;padding:10px;font-size:14px;color:{text_color};}}QLineEdit{{background-color:{light_bg};border:1px solid {dark_border};border-radius:5px;padding:8px;font-size:14px;color:{text_color};}}QLineEdit:focus{{border:1px solid {accent_color};}}QLineEdit[objectName^="chat_input"]{{border-radius:15px;padding-left:15px;padding-right:10px;}}QPushButton{{background-color:{medium_border};color:{text_color};border:none;border-radius:5px;padding:8px 15px;font-size:14px;font-weight:bold;min-width:90px;outline:none;}}QPushButton:hover{{background-color:{secondary_btn_hover};}}QPushButton:pressed{{background-color:{secondary_btn_pressed};}}QPushButton:disabled{{background-color:#444;color:#888;}}QPushButton#send_button,QPushButton#chat_send_button,QPushButton#connect_button,QPushButton#send_file_button,QPushButton#resume_button,QPushButton#create_group_button,QPushButton#accept_invite_button,QPushButton#approve_join_button{{background-color:{accent_color};color:white;}}QPushButton#send_button:hover,QPushButton#chat_send_button:hover,QPushButton#connect_button:hover,QPushButton#send_file_button:hover,QPushButton#resume_button:hover,QPushButton#create_group_button:hover,QPushButton#accept_invite_button:hover,QPushButton#approve_join_button:hover{{background-color:{accent_hover};}}QPushButton#send_button:pressed,QPushButton#chat_send_button:pressed,QPushButton#connect_button:pressed,QPushButton#send_file_button:pressed,QPushButton#resume_button:pressed,QPushButton#create_group_button:pressed,QPushButton#accept_invite_button:pressed,QPushButton#approve_join_button:pressed{{background-color:{accent_pressed};}}QPushButton#send_button:disabled,QPushButton#chat_send_button:disabled,QPushButton#connect_button:disabled,QPushButton#send_file_button:disabled,QPushButton#resume_button:disabled,QPushButton#create_group_button:disabled,QPushButton#accept_invite_button:disabled,QPushButton#approve_join_button:disabled{{background-color:#554433;color:#aaaaaa;}}QPushButton#disconnect_button,QPushButton#choose_file_button,QPushButton#pause_button,QPushButton#decline_invite_button,QPushButton#deny_join_button{{background-color:transparent;border:1px solid {accent_color};color:{accent_color};}}QPushButton#disconnect_button:hover,QPushButton#choose_file_button:hover,QPushButton#pause_button:hover,QPushButton#decline_invite_button:hover,QPushButton#deny_join_button:hover{{background-color:rgba(255,102,0,0.1);color:{accent_hover};border-color:{accent_hover};}}QPushButton#disconnect_button:pressed,QPushButton#choose_file_button:pressed,QPushButton#pause_button:pressed,QPushButton#decline_invite_button:pressed,QPushButton#deny_join_button:pressed{{background-color:rgba(255,102,0,0.2);color:{accent_pressed};border-color:{accent_pressed};}}QPushButton#disconnect_button:disabled,QPushButton#choose_file_button:disabled,QPushButton#pause_button:disabled,QPushButton#decline_invite_button:disabled,QPushButton#deny_join_button:disabled{{background-color:transparent;border-color:#666;color:#666;}}QPushButton#chat_send_button{{border-radius:16px;min-width:32px;padding:0;}}QProgressBar{{border:1px solid {dark_border};border-radius:5px;text-align:center;font-size:12px;font-weight:bold;color:{text_color};background-color:{light_bg};}}QProgressBar::chunk{{background-color:{accent_color};border-radius:4px;margin:1px;}}QStatusBar{{background-color:{dark_bg};color:{dim_text_color};font-size:12px;border-top:1px solid {dark_border};}}QStatusBar::item{{border:none;}}QMenuBar{{background-color:{medium_bg};color:{text_color};border-bottom:1px solid {dark_border};}}QMenuBar::item{{background:transparent;padding:5px 10px;font-size:13px;}}QMenuBar::item:selected{{background:{medium_border};}}QMenu{{background-color:{medium_bg};border:1px solid {medium_border};color:{text_color};padding:5px;}}QMenu::item{{padding:8px 20px;}}QMenu::item:selected{{background-color:{accent_color};color:#000000;}}QMenu::separator{{height:1px;background:{medium_border};margin:5px 10px;}}QSplitter::handle{{background-color:{dark_border};}}QSplitter::handle:horizontal{{width:1px;}}QSplitter::handle:vertical{{height:1px;}}QSplitter::handle:pressed{{background-color:{accent_color};}}QScrollBar:vertical{{border:none;background:{medium_bg};width:10px;margin:0px;}}QScrollBar::handle:vertical{{background:{medium_border};min-height:20px;border-radius:5px;}}QScrollBar::handle:vertical:hover{{background:#555;}}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{border:none;background:none;height:0px;}}QScrollBar:horizontal{{border:none;background:{medium_bg};height:10px;margin:0px;}}QScrollBar::handle:horizontal{{background:{medium_border};min-width:20px;border-radius:5px;}}QScrollBar::handle:horizontal:hover{{background:#555;}}QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{border:none;background:none;width:0px;}}QLabel{{color:{text_color};padding-bottom:2px;}}QLabel#error_label{{color:#FFAAAA;font-size:12px;qproperty-alignment:'AlignCenter';}}"""
        self.setStyleSheet(stylesheet_template.format(dark_bg=dark_bg,medium_bg=medium_bg,light_bg=light_bg,dark_border=dark_border,medium_border=medium_border,text_color=text_color,dim_text_color=dim_text_color,accent_color=accent_color,accent_hover=accent_hover,accent_pressed=accent_pressed,font_family=font_family, secondary_btn_hover=secondary_btn_hover, secondary_btn_pressed=secondary_btn_pressed));font=QFont(font_family.split(',')[0].strip(),10);QApplication.instance().setFont(font)


# --- Main Execution --- #
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    dark_palette=QPalette();dark_palette.setColor(QPalette.ColorRole.Window,QColor(30,30,30));dark_palette.setColor(QPalette.ColorRole.WindowText,QColor(224,224,224));dark_palette.setColor(QPalette.ColorRole.Base,QColor(45,45,45));dark_palette.setColor(QPalette.ColorRole.AlternateBase,QColor(37,37,38));dark_palette.setColor(QPalette.ColorRole.ToolTipBase,QColor(30,30,30));dark_palette.setColor(QPalette.ColorRole.ToolTipText,QColor(224,224,224));dark_palette.setColor(QPalette.ColorRole.Text,QColor(224,224,224));dark_palette.setColor(QPalette.ColorRole.Button,QColor(37,37,38));dark_palette.setColor(QPalette.ColorRole.ButtonText,QColor(224,224,224));dark_palette.setColor(QPalette.ColorRole.BrightText,QColor(255,102,0));dark_palette.setColor(QPalette.ColorRole.Link,QColor(42,130,218));dark_palette.setColor(QPalette.ColorRole.Highlight,QColor(255,102,0));dark_palette.setColor(QPalette.ColorRole.HighlightedText,QColor(0,0,0));dark_palette.setColor(QPalette.ColorRole.PlaceholderText,QColor(160,160,160));disabled_text=QColor(120,120,120);disabled_button=QColor(60,60,60);dark_palette.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.ButtonText,disabled_text);dark_palette.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.WindowText,disabled_text);dark_palette.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.Text,disabled_text);dark_palette.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.Button,disabled_button);dark_palette.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.Base,QColor(40,40,40));
    app.setPalette(dark_palette)
    app.setApplicationName("P2PChat"); app.setOrganizationName("YourOrg"); app.setWindowIcon(QIcon.fromTheme("network-transmit-receive", QIcon("./icons/app_icon.png")))

    login_window = LoginWindow()
    login_window.show()
    exit_code = app.exec()
    logger.info(f"Application exiting with code {exit_code}")
    shutdown_event.set() # Ensure shutdown is signalled on exit
   
    time.sleep(0.5)
    sys.exit(exit_code)
