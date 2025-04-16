import asyncio
import logging
import websockets
import os
import platform
import json
import hashlib
import aiofiles
import netifaces
import uuid
import time
import ssl
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from appdirs import user_config_dir
from websockets.connection import State

from utils.file_validation import check_file_size, check_disk_space, safe_close_file
from networking.utils import get_own_ip, get_peer_display_name, get_own_display_name
from networking.shared_state import (
    active_transfers, message_queue, connections, user_data, peer_public_keys,
    peer_usernames, peer_device_ids, shutdown_event, groups, pending_invites,
    pending_join_requests, pending_approvals, connection_denials,
    connections_lock, active_transfers_lock, peer_data_lock,
    groups_lock, pending_lock, outgoing_transfers_by_peer,
    connection_attempts, connection_attempts_lock
)
from networking.file_transfer import FileTransfer, TransferState, compute_hash
from networking.groups import (
     send_group_create_message, send_group_invite_message, send_group_invite_response,
     send_group_join_request, send_group_join_response, send_group_update_message
)

logger = logging.getLogger(__name__)

CONFIG_DIR = user_config_dir("P2PChat", "YourOrg")
KEY_FILE = os.path.join(CONFIG_DIR, "key.pem")
CERT_FILE = os.path.join(CONFIG_DIR, "cert.pem")

async def initialize_user_config():
    global user_data
    global KEY_FILE

    os.makedirs(CONFIG_DIR, exist_ok=True)
    config_path = os.path.join(CONFIG_DIR, "config.json")
    key_path = os.path.join(CONFIG_DIR, "p2p_key.pem")
    pub_key_path = os.path.join(CONFIG_DIR, "p2p_key.pub")

    if os.path.exists(config_path):
        try:
            async with aiofiles.open(config_path, "r") as f:
                content = await f.read()
                loaded_data = json.loads(content)
                user_data.update(loaded_data)
                logger.info(f"Loaded config from {config_path}")
        except (json.JSONDecodeError, FileNotFoundError, TypeError) as e:
            logger.warning(f"Could not load or parse config file {config_path}: {e}. Will re-initialize missing parts.")

    keys_need_processing = False
    if "private_key" not in user_data or isinstance(user_data.get("private_key"), str):
        keys_need_processing = True
    if "public_key" not in user_data or isinstance(user_data.get("public_key"), str):
        keys_need_processing = True

    if keys_need_processing:
        if os.path.exists(key_path) and os.path.exists(pub_key_path):
            try:
                async with aiofiles.open(key_path, "rb") as f:
                    private_pem = await f.read()
                    user_data["private_key"] = serialization.load_pem_private_key(private_pem, password=None)
                async with aiofiles.open(pub_key_path, "rb") as f:
                    public_pem = await f.read()
                    user_data["public_key"] = serialization.load_pem_public_key(public_pem)
                logger.info(f"Loaded existing RSA keys from {key_path} and {pub_key_path}")
                keys_need_processing = False
            except Exception as e:
                logger.error(f"Failed to load existing keys from files: {e}. Will attempt generation.")
                user_data.pop("private_key", None)
                user_data.pop("public_key", None)
                keys_need_processing = True

        if keys_need_processing:
            deserialized_from_json = False
            try:
                if isinstance(user_data.get("private_key"), str):
                    user_data["private_key"] = serialization.load_pem_private_key(user_data["private_key"].encode(), password=None)
                    deserialized_from_json = True
                if isinstance(user_data.get("public_key"), str):
                    user_data["public_key"] = serialization.load_pem_public_key(user_data["public_key"].encode())
                    deserialized_from_json = True
                if deserialized_from_json:
                    logger.info("Deserialized RSA keys from loaded config JSON.")
                    keys_need_processing = False
            except Exception as e:
                logger.error(f"Failed to deserialize keys from config JSON: {e}. Generating new keys.")
                user_data.pop("private_key", None)
                user_data.pop("public_key", None)
                keys_need_processing = True

        if keys_need_processing:
            logger.info("Generating new RSA key pair...")
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            user_data["private_key"] = private_key
            user_data["public_key"] = public_key
            try:
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                async with aiofiles.open(key_path, "wb") as f: await f.write(private_pem)
                async with aiofiles.open(pub_key_path, "wb") as f: await f.write(public_pem)
                logger.info(f"Saved new RSA keys to {key_path} and {pub_key_path}")
            except Exception as e:
                logger.error(f"Failed to save newly generated keys: {e}")

    if "device_id" not in user_data:
        user_data["device_id"] = str(uuid.uuid4())
        logger.info(f"Generated new device ID: {user_data['device_id']}")
        await save_config_json(config_path, user_data, "new device ID")

    user_data['key_path'] = KEY_FILE
    user_data['cert_path'] = CERT_FILE

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        logger.info(f"Generating self-signed SSL certificate ({CERT_FILE}) and ensuring key ({KEY_FILE})...")
        try:
            if "private_key" not in user_data or not isinstance(user_data["private_key"], rsa.RSAPrivateKey):
                 logger.error("RSA private key missing or not deserialized, cannot generate SSL certificate.")
                 raise ValueError("RSA private key required for SSL certificate generation.")
            if "public_key" not in user_data or not isinstance(user_data["public_key"], rsa.RSAPublicKey):
                 logger.error("RSA public key missing or not deserialized, cannot generate SSL certificate.")
                 raise ValueError("RSA public key required for SSL certificate generation.")

            ssl_private_key = user_data["private_key"]
            ssl_public_key = user_data["public_key"]

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Localhost"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"P2PChatOrg"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"p2pchat-{user_data.get('device_id', 'unknown-peer')}.local"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                ssl_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                 x509.SubjectAlternativeName([
                     x509.DNSName(u"localhost"),
                 ]),
                 critical=False,
            ).sign(ssl_private_key, crypto_hashes.SHA256())

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            async with aiofiles.open(CERT_FILE, "wb") as f:
                await f.write(cert_pem)
            logger.info(f"Saved self-signed certificate to {CERT_FILE}")

            if KEY_FILE != key_path:
                logger.info(f"Saving private key specifically for SSL to {KEY_FILE}")
                private_pem_ssl = ssl_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                async with aiofiles.open(KEY_FILE, "wb") as f:
                    await f.write(private_pem_ssl)
            else:
                if not os.path.exists(key_path):
                    logger.error(f"Main private key file {key_path} missing after generation attempt!")
                logger.info(f"Using existing private key {KEY_FILE} for SSL.")

            user_data['key_path'] = KEY_FILE

        except ValueError as ve:
            logger.error(f"Cannot generate SSL cert: {ve}")
            user_data.pop('key_path', None)
            user_data.pop('cert_path', None)
        except Exception as e:
            logger.exception(f"Failed to generate or save SSL certificate/key: {e}")
            user_data.pop('key_path', None)
            user_data.pop('cert_path', None)
    else:
        logger.info(f"Found existing SSL certificate ({CERT_FILE}) and key ({KEY_FILE}).")

    if "original_username" not in user_data:
        user_data["original_username"] = f"User_{platform.node()[:8]}"
        logger.warning(f"Username not found, set default: {user_data['original_username']}")
        await save_config_json(config_path, user_data, "default username")

    logger.info("User config initialization complete.")
    log_safe_data = {
        k: (v if k not in ["private_key", "public_key"] else f"<{type(v).__name__}>")
        for k, v in user_data.items()
    }
    logger.debug(f"User Data State: {log_safe_data}")


async def save_config_json(config_path, data_to_save, reason="update"):
    try:
        save_data = data_to_save.copy()
        if isinstance(save_data.get("private_key"), rsa.RSAPrivateKey):
            save_data["private_key"] = save_data["private_key"].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        if isinstance(save_data.get("public_key"), rsa.RSAPublicKey):
            save_data["public_key"] = save_data["public_key"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

        async with aiofiles.open(config_path, "w") as f:
            await f.write(json.dumps(save_data, indent=4))
        logger.info(f"Saved config to {config_path} (Reason: {reason})")
    except Exception as e:
        logger.error(f"Failed to save config to {config_path}: {e}")


async def create_new_user_config(config_file_path, provided_username=None):
    logger.warning("create_new_user_config called - ensure initialize_user_config handles saving.")
    if not provided_username:
        logger.critical("Username not provided for new config creation.")
        raise ValueError("Username required for new config creation")

    original_username = provided_username
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    device_id = str(uuid.uuid4())

    new_user_data = {
        "original_username": original_username,
        "device_id": device_id,
        "public_key": public_key,
        "private_key": private_key,
    }

    config_data_to_save = {
        "original_username": original_username,
        "device_id": device_id,
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "private_key": private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
    }

    try:
        json_string = json.dumps(config_data_to_save, indent=4)
        async with aiofiles.open(config_file_path, "w") as f:
            await f.write(json_string)
        logger.info(f"New user config JSON created for {original_username} at {config_file_path}")

        key_path = os.path.join(CONFIG_DIR, "p2p_key.pem")
        pub_key_path = os.path.join(CONFIG_DIR, "p2p_key.pub")
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        async with aiofiles.open(key_path, "wb") as f: await f.write(private_pem)
        async with aiofiles.open(pub_key_path, "wb") as f: await f.write(public_pem)
        logger.info(f"Saved separate keys to {key_path} and {pub_key_path}")

        user_data.clear()
        user_data.update(new_user_data)

    except Exception as e:
        logger.exception(f"FATAL: Could not write config/key files for {original_username}: {e}")
        await message_queue.put({"type": "log", "message": f"FATAL: Cannot write config/key file: {e}", "level": logging.CRITICAL})
        raise


async def connect_to_peer(peer_ip, requesting_username, target_username, port=8765):
    async with connections_lock:
        if peer_ip in connections:
            logger.warning(f"Already connected to {peer_ip} ({target_username}). Aborting connect.")
            await message_queue.put({"type": "log", "message": f"Already connected to {target_username}.", "level": logging.WARNING})
            return False

    connection_timestamp = time.time()
    my_device_id = user_data.get("device_id", "")
    async with connection_attempts_lock:
        connection_attempts[peer_ip] = ("outgoing", connection_timestamp, my_device_id)
        logger.debug(f"Recorded outgoing connection attempt to {peer_ip} at {connection_timestamp}")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    uri = f"wss://{peer_ip}:{port}"; websocket = None
    try:
        logger.info(f"Attempting to connect securely to {target_username} at {uri}")
        websocket = await asyncio.wait_for(
            websockets.connect(
                uri,
                ping_interval=20,
                ping_timeout=15,
                max_size=10 * 1024 * 1024,
                ssl=ssl_context
            ),
            timeout=20.0
        )
        logger.debug(f"Secure WebSocket connection opened to {peer_ip}")

        own_ip = await get_own_ip()
        await websocket.send(f"INIT {own_ip}")
        ack = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        if ack != "INIT_ACK": raise ConnectionAbortedError(f"Invalid INIT_ACK from {peer_ip}: {ack}")
        logger.debug(f"INIT_ACK received from {peer_ip}")

        public_key_pem = user_data["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        req_msg = json.dumps({
            "type": "CONNECTION_REQUEST",
            "requesting_username": requesting_username,
            "device_id": user_data["device_id"],
            "target_username": target_username,
            "key": public_key_pem
        })
        await websocket.send(req_msg)

        response_raw = await asyncio.wait_for(websocket.recv(), timeout=65.0)
        response_data = json.loads(response_raw)
        if response_data["type"] != "CONNECTION_RESPONSE" or not response_data.get("approved"):
            reason = response_data.get("reason", "No reason provided")
            raise ConnectionRefusedError(f"Connection denied by {target_username}: {reason}")
        logger.info(f"Connection approved by {target_username} ({peer_ip})")

        await websocket.send(json.dumps({
            "type": "IDENTITY",
            "username": user_data["original_username"],
            "device_id": user_data["device_id"],
            "key": public_key_pem
        }))

        identity_raw = await asyncio.wait_for(websocket.recv(), timeout=15.0)
        identity_data = json.loads(identity_raw)

        if identity_data["type"] == "IDENTITY":
            peer_key_pem = identity_data["key"]
            peer_uname = identity_data["username"]
            peer_dev_id = identity_data["device_id"]

            should_abort = False
            async with connection_attempts_lock:
                peer_attempt = connection_attempts.get(peer_ip)
                if peer_attempt and peer_attempt[0] == "incoming" and peer_attempt[2] == peer_dev_id:
                    if my_device_id < peer_dev_id:
                        logger.info(f"Tie-breaking: Continuing outgoing connection to {target_username} (My ID {my_device_id} < Peer ID {peer_dev_id}).")
                    else:
                        logger.info(f"Tie-breaking: Aborting outgoing connection to {target_username} (My ID {my_device_id} >= Peer ID {peer_dev_id}). Peer should keep incoming.")
                        should_abort = True
                async with connections_lock:
                     if peer_ip in connections:
                         logger.warning(f"Tie-breaking/Race: An incoming connection from {target_username} was established while connecting. Aborting outgoing.")
                         should_abort = True

            if should_abort:
                await websocket.close(1000, reason="Connection tie-breaking resolution")
                return False

            async with connections_lock:
                if peer_ip in connections:
                    logger.warning(f"Race condition: Connection to {peer_ip} established by another task just before finalization. Aborting this one.")
                    await websocket.close(1000, reason="Connection race condition")
                    return False
                connections[peer_ip] = websocket

            async with peer_data_lock:
                peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
                peer_usernames[peer_uname] = peer_ip
                peer_device_ids[peer_ip] = peer_dev_id

            display_name = get_peer_display_name(peer_ip)
            logger.info(f"Secure connection established with {display_name} ({peer_ip})")
            await message_queue.put({"type": "connection_status", "peer_ip": peer_ip, "connected": True})
            await message_queue.put({"type": "log", "message": f"Connected securely to {display_name}"})

            asyncio.create_task(receive_peer_messages(websocket, peer_ip), name=f"RecvMsg-{peer_ip}")
            return True

        else:
            raise ConnectionAbortedError("Invalid IDENTITY response from peer.")

    except (ConnectionRefusedError, ConnectionAbortedError) as e:
        logger.warning(f"Connection to {target_username} ({peer_ip}) failed: {e}")
        await message_queue.put({"type": "log", "message": f"Connection to {target_username} failed: {e}", "level": logging.WARNING})
        if websocket and websocket.state == State.OPEN: await websocket.close(1000, reason=str(e))
        return False
    except (websockets.exceptions.InvalidURI, websockets.exceptions.WebSocketException, ssl.SSLError, OSError, asyncio.TimeoutError) as e:
        logger.error(f"Connection attempt to {target_username} ({peer_ip}) failed: {type(e).__name__}: {e}")
        await message_queue.put({"type": "log", "message": f"Could not connect to {target_username}: {type(e).__name__}", "level": logging.ERROR})
        if websocket and websocket.state == State.OPEN: await websocket.close(1011, reason="Connection error")
        return False
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response from {target_username} ({peer_ip}): {e}")
        await message_queue.put({"type": "log", "message": f"Invalid response from {target_username}.", "level": logging.ERROR})
        if websocket and websocket.state == State.OPEN: await websocket.close(1002, reason="Invalid JSON response")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error connecting to {target_username} ({peer_ip}): {e}")
        await message_queue.put({"type": "log", "message": f"Error connecting to {target_username}: {e}", "level": logging.ERROR})
        if websocket and websocket.state == State.OPEN: await websocket.close(1011, reason="Unexpected error")
        return False
    finally:
        async with connection_attempts_lock:
            attempt_info = connection_attempts.get(peer_ip)
            if attempt_info and attempt_info[0] == "outgoing" and attempt_info[1] == connection_timestamp:
                connection_attempts.pop(peer_ip, None)
                logger.debug(f"Cleaned up outgoing connection attempt record for {peer_ip}")


async def disconnect_from_peer(peer_ip):
    display_name = get_peer_display_name(peer_ip)
    logger.info(f"Initiating disconnect from {display_name} ({peer_ip})...")

    websocket = None
    async with connections_lock:
        websocket = connections.pop(peer_ip, None)

    async with peer_data_lock:
        peer_public_keys.pop(peer_ip, None)
        peer_device_ids.pop(peer_ip, None)
        username_to_remove = next((uname for uname, ip_addr in peer_usernames.items() if ip_addr == peer_ip), None)
        if username_to_remove:
            peer_usernames.pop(username_to_remove, None)
            logger.debug(f"Removed username mapping for {username_to_remove} ({peer_ip})")

    async with active_transfers_lock:
        removed_count = len(outgoing_transfers_by_peer.pop(peer_ip, []))
        if removed_count > 0:
             logger.debug(f"Cleared tracking for {removed_count} outgoing transfers to {peer_ip}.")

    closed_successfully = False
    if websocket:
        if websocket.state == State.OPEN:
            try:
                await asyncio.wait_for(websocket.close(code=1000, reason="User initiated disconnect"), timeout=5.0)
                logger.info(f"Successfully closed connection to {display_name} ({peer_ip})")
                closed_successfully = True
            except asyncio.TimeoutError:
                 logger.warning(f"Timeout closing connection to {peer_ip}. May already be closed.")
                 closed_successfully = False
            except Exception as e:
                 logger.error(f"Error during websocket close for {peer_ip}: {e}")
                 closed_successfully = False
        else:
            logger.info(f"Connection to {display_name} ({peer_ip}) was already closed (State: {websocket.state}).")
            closed_successfully = True
    else:
        logger.info(f"No active connection object found for {peer_ip} to disconnect.")
        closed_successfully = True

    await message_queue.put({"type": "connection_status", "peer_ip": peer_ip, "connected": False})

    if websocket:
        if closed_successfully and websocket.state != State.OPEN :
             await message_queue.put({"type": "log", "message": f"Disconnected from {display_name}"})
        else:
             await message_queue.put({"type": "log", "message": f"Finished disconnect process for {display_name} (may not have closed gracefully).", "level": logging.WARNING})
    else:
         await message_queue.put({"type": "log", "message": f"No active connection to {display_name} to disconnect.", "level": logging.INFO})

    return closed_successfully


async def handle_incoming_connection(websocket, peer_ip):
    approved = False; requesting_display_name = f"Peer@{peer_ip}"
    requesting_username = "Unknown"; approval_key = None; req_dev_id = None
    peer_key_pem = None; connection_stored = False; connection_timestamp = None

    async with connections_lock:
        if peer_ip in connections:
            logger.warning(f"Duplicate incoming connection attempt from {peer_ip}. Closing new one.")
            await websocket.close(1008, reason="Already connected")
            return False

    try:
        init_message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
        if shutdown_event.is_set(): await websocket.close(1001); return False
        if not isinstance(init_message, str) or not init_message.startswith("INIT "): raise ValueError("Invalid INIT message")
        _, sender_ip = init_message.split(" ", 1); logger.info(f"Received INIT from {peer_ip}")

        async with connections_lock:
            if peer_ip in connections: logger.warning(f"Duplicate connection from {peer_ip} (race)."); await websocket.close(1008); return False

        await websocket.send("INIT_ACK")
        request_raw = await asyncio.wait_for(websocket.recv(), timeout=30.0)
        request_data = json.loads(request_raw)

        if request_data["type"] == "CONNECTION_REQUEST":
            requesting_username = request_data["requesting_username"]
            target_username = request_data["target_username"]
            peer_key_pem = request_data["key"]
            req_dev_id = request_data["device_id"]
            requesting_display_name = f"{requesting_username}({req_dev_id[:8]})"
            logger.info(f"Connection request from {requesting_display_name} targeting {target_username}")

            if target_username != user_data["original_username"]:
                raise ConnectionRefusedError(f"Request targets incorrect user '{target_username}'")

            connection_timestamp = time.time()
            my_device_id = user_data.get("device_id", "")
            handle_this_connection = True

            async with connection_attempts_lock:
                connection_attempts[peer_ip] = ("incoming", connection_timestamp, my_device_id)
                logger.debug(f"Recorded incoming connection attempt from {peer_ip} at {connection_timestamp}")

                outgoing_attempt = connection_attempts.get(peer_ip)
                if outgoing_attempt and outgoing_attempt[0] == "outgoing" and outgoing_attempt[2]:
                    peer_recorded_dev_id = outgoing_attempt[2]
                    if my_device_id and req_dev_id:
                        if my_device_id > req_dev_id:
                            logger.info(f"Tie-breaking: Accepting incoming connection from {requesting_display_name} (My ID {my_device_id} > Peer ID {req_dev_id}).")
                            handle_this_connection = True
                        else:
                            logger.info(f"Tie-breaking: Rejecting incoming connection from {requesting_display_name} (My ID {my_device_id} <= Peer ID {req_dev_id}). Outgoing should win.")
                            handle_this_connection = False
                            await websocket.close(1000, reason="Connection superseded by outgoing connection")
                    else:
                        logger.warning(f"Cannot perform tie-breaking for {requesting_display_name} due to missing device IDs. Accepting incoming.")
                        handle_this_connection = True

            if not handle_this_connection:
                return False

            approval_key = (peer_ip, requesting_username)
            denial_key = (target_username, requesting_username)
            denial_count = connection_denials.get(denial_key, 0)

            if denial_count >= 3:
                raise ConnectionRefusedError("Connection blocked (previously denied 3+ times)")

            approval_future = asyncio.Future()
            pending_approvals[approval_key] = approval_future
            await message_queue.put({
                "type": "approval_request",
                "peer_ip": peer_ip,
                "requesting_username": requesting_display_name
            })

            try:
                approved = await asyncio.wait_for(approval_future, timeout=60.0)
            except asyncio.TimeoutError:
                logger.info(f"Approval timeout for {requesting_display_name}")
                approved = False
            finally:
                pending_approvals.pop(approval_key, None)
                approval_key = None

            if not approved:
                 current_denials = connection_denials.get(denial_key, 0) + 1
                 connection_denials[denial_key] = current_denials
                 deny_reason = "Connection denied by user or timeout"
                 await message_queue.put({"type": "log", "message": f"Denied connection from {requesting_display_name} ({current_denials}/3)"})
                 if current_denials >= 3:
                     await message_queue.put({"type": "log", "message": f"{requesting_display_name} blocked due to repeated denials."})
                     deny_reason = "Connection blocked (previous denials)"
                 try:
                     await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": deny_reason}))
                 except Exception as send_err:
                      logger.warning(f"Could not send denial response to {peer_ip}: {send_err}")
                 raise ConnectionRefusedError(deny_reason)

            logger.info(f"Connection approved for {requesting_display_name}")
            await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": True}))

            own_public_key_pem = user_data["public_key"].public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            await websocket.send(json.dumps({
                "type": "IDENTITY",
                "username": user_data["original_username"],
                "device_id": user_data["device_id"],
                "key": own_public_key_pem
            }))

            identity_raw = await asyncio.wait_for(websocket.recv(), timeout=15.0)
            identity_data = json.loads(identity_raw)

            if identity_data["type"] == "IDENTITY" and \
               identity_data["username"] == requesting_username and \
               identity_data["device_id"] == req_dev_id:

                 async with connections_lock:
                     if peer_ip in connections:
                         logger.warning(f"Race condition: Another connection to {peer_ip} stored before this one finished. Closing.")
                         await websocket.close(1008, reason="Connection race condition")
                         return False
                     connections[peer_ip] = websocket
                     connection_stored = True

                 async with peer_data_lock:
                     peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
                     peer_usernames[requesting_username] = peer_ip
                     peer_device_ids[peer_ip] = req_dev_id

                 final_display_name = get_peer_display_name(peer_ip)
                 logger.info(f"Secure connection established with {final_display_name} ({peer_ip})")
                 await message_queue.put({"type": "connection_status", "peer_ip": peer_ip, "connected": True})
                 await message_queue.put({"type": "log", "message": f"Connected securely to {final_display_name}"})
                 return True

            else:
                logger.error(f"Received invalid final IDENTITY from {requesting_display_name}. Expected: {requesting_username}/{req_dev_id}, Got: {identity_data.get('username')}/{identity_data.get('device_id')}")
                raise ConnectionAbortedError("Invalid final IDENTITY received from peer")
        else:
            raise ValueError(f"Unexpected message type after INIT_ACK: {request_data.get('type')}")

    except (ConnectionRefusedError, ConnectionAbortedError, ValueError) as e:
        logger.warning(f"Incoming connection from {peer_ip} ({requesting_display_name}) failed: {e}")
        if websocket and websocket.state == State.OPEN:
            try: await websocket.close(1002, reason=f"Handshake error: {e}")
            except: pass
        return False
    except (websockets.exceptions.ConnectionClosed, websockets.exceptions.WebSocketException, ssl.SSLError, OSError, asyncio.TimeoutError) as e:
        logger.warning(f"Network/SSL error during handshake with {peer_ip}: {type(e).__name__}: {e}")
        if websocket and websocket.state == State.OPEN:
            try: await websocket.close(1011, reason="Handshake network error")
            except: pass
        return False
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON during handshake with {peer_ip}: {e}")
        if websocket and websocket.state == State.OPEN:
            try: await websocket.close(1002, reason="Invalid JSON during handshake")
            except: pass
        return False
    except Exception as e:
        logger.exception(f"Unexpected error during incoming handshake with {peer_ip}: {e}")
        if websocket and websocket.state == State.OPEN:
            try: await websocket.close(1011, reason="Unexpected server error during handshake")
            except: pass
        return False
    finally:
        if approval_key and approval_key in pending_approvals:
            pending_approvals.pop(approval_key, None)
            logger.debug(f"Cleaned up pending approval key {approval_key} in finally block.")

        if connection_timestamp:
            async with connection_attempts_lock:
                attempt_info = connection_attempts.get(peer_ip)
                if attempt_info and attempt_info[0] == "incoming" and attempt_info[1] == connection_timestamp:
                    connection_attempts.pop(peer_ip, None)
                    logger.debug(f"Cleaned up incoming connection attempt record for {peer_ip}")

        if not connection_stored:
            async with connections_lock:
                if peer_ip in connections:
                     logger.debug(f"Cleaning up potentially stored connection for {peer_ip} after handshake failure in finally block.")
                     connections.pop(peer_ip, None)
                     async with peer_data_lock:
                         peer_public_keys.pop(peer_ip, None)
                         peer_device_ids.pop(peer_ip, None)
                         uname = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
                         if uname: peer_usernames.pop(uname, None)


async def send_message_to_peers(message, target_peer_ip=None):
    if not isinstance(message, str) or not message:
        logger.warning("Attempted send empty message.")
        return False

    peers_to_send = {}
    sent_count = 0

    async with connections_lock:
        if target_peer_ip:
            ws = connections.get(target_peer_ip)
            if ws:
                peers_to_send[target_peer_ip] = ws
            else:
                display_name_target = get_peer_display_name(target_peer_ip)
                logger.warning(f"Msg Send Fail: Not connected to {display_name_target} ({target_peer_ip})")
                await message_queue.put({"type":"log","message":f"Cannot send message: Not connected to {display_name_target}","level":logging.WARNING})
                return False
        else:
            peers_to_send = connections.copy()

    if not peers_to_send:
         if target_peer_ip is None:
             await message_queue.put({"type":"log","message":"No connected peers to send broadcast message to."})
             logger.info("Msg Send Fail: No connected peers for broadcast.")
         return False

    for ip, ws in peers_to_send.items():
        display_name = get_peer_display_name(ip)

        if ws.state == State.OPEN:
            peer_public_key = None
            async with peer_data_lock:
                peer_public_key = peer_public_keys.get(ip)

            if not peer_public_key:
                logger.warning(f"No public key found for {display_name} ({ip}) while sending message. Skipping.")
                continue

            try:
                encrypted_message_bytes = peer_public_key.encrypt(
                    message.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_message_hex = encrypted_message_bytes.hex()

                payload = json.dumps({"type": "MESSAGE", "message": encrypted_message_hex})

                await asyncio.wait_for(ws.send(payload), timeout=10.0)
                sent_count += 1
                logger.debug(f"Sent encrypted message to {display_name} ({ip})")

            except asyncio.TimeoutError:
                logger.error(f"Timeout sending message to {display_name} ({ip}).")
            except (websockets.exceptions.ConnectionClosed, websockets.exceptions.WebSocketException) as e:
                 logger.error(f"Connection error sending message to {display_name} ({ip}): {e}")
            except Exception as e:
                logger.error(f"Failed to encrypt or send message to {display_name} ({ip}): {e}", exc_info=True)

        else:
            logger.warning(f"Attempted to send message to non-open connection: {display_name} ({ip}), state: {ws.state}")

    return sent_count > 0


async def receive_peer_messages(websocket, peer_ip):
    display_name = get_peer_display_name(peer_ip)
    logger.info(f"Starting message receiver loop for {display_name} ({peer_ip})")
    current_receiving_transfer = None

    try:
        async for message in websocket:
            if shutdown_event.is_set():
                logger.debug(f"Shutdown event set, stopping receive loop for {display_name}.")
                break

            is_binary = isinstance(message, bytes)

            if is_binary:
                transfer = current_receiving_transfer
                if transfer:
                    try:
                        async with transfer.condition:
                            while transfer.state == TransferState.PAUSED and not shutdown_event.is_set():
                                logger.debug(f"Receiving loop for {transfer.transfer_id[:8]} paused. Waiting...")
                                await transfer.condition.wait()
                            if shutdown_event.is_set(): break

                            if transfer.state != TransferState.IN_PROGRESS:
                                logger.warning(f"Received binary data for non-active transfer {transfer.transfer_id[:8]} from {display_name}. State: {transfer.state}. Ignoring.")
                                continue

                            if transfer.file_handle:
                                await transfer.file_handle.write(message)
                            else:
                                logger.error(f"File handle closed unexpectedly for transfer {transfer.transfer_id[:8]}. Failing transfer.")
                                await transfer.fail("File handle missing")
                                current_receiving_transfer = None
                                continue

                            transfer.transferred_size += len(message)
                            if transfer.hash_algo:
                                transfer.hash_algo.update(message)

                            if transfer.transferred_size >= transfer.total_size:
                                logger.info(f"Received expected size for transfer {transfer.transfer_id[:8]} ({transfer.transferred_size}/{transfer.total_size}). Closing file.")
                                await safe_close_file(transfer.file_handle)
                                transfer.file_handle = None

                                final_state = TransferState.COMPLETED
                                completion_msg = f"Successfully received '{os.path.basename(transfer.file_path)}' from {display_name}."

                                if transfer.expected_hash:
                                    calculated_hash = transfer.hash_algo.hexdigest()
                                    logger.debug(f"Verifying hash for {transfer.transfer_id[:8]}. Expected: {transfer.expected_hash}, Calculated: {calculated_hash}")
                                    if calculated_hash == transfer.expected_hash:
                                        logger.info(f"File hash verified successfully for transfer {transfer.transfer_id[:8]}")
                                    else:
                                        final_state = TransferState.FAILED
                                        completion_msg = f"Hash mismatch for received file '{os.path.basename(transfer.file_path)}' from {display_name}. File deleted."
                                        logger.error(f"Hash mismatch for transfer {transfer.transfer_id[:8]}. Expected: {transfer.expected_hash}, Got: {calculated_hash}")
                                        try:
                                            if hasattr(aiofiles, 'os') and hasattr(aiofiles.os, 'remove'):
                                                await aiofiles.os.remove(transfer.file_path)
                                            else:
                                                os.remove(transfer.file_path)
                                            logger.info(f"Deleted corrupted file due to hash mismatch: {transfer.file_path}")
                                        except OSError as rm_err:
                                            logger.error(f"Failed to delete corrupted file {transfer.file_path}: {rm_err}")
                                else:
                                    completion_msg += " (No hash provided for verification)."
                                    logger.info(f"Transfer {transfer.transfer_id[:8]} completed without hash verification.")

                                transfer.state = final_state
                                await message_queue.put({"type": "log", "message": completion_msg, "level": logging.ERROR if final_state == TransferState.FAILED else logging.INFO})
                                await message_queue.put({"type": "transfer_update"})
                                current_receiving_transfer = None

                    except Exception as write_err:
                        logger.exception(f"Error processing file chunk for transfer {getattr(transfer, 'transfer_id', 'N/A')[:8]} from {display_name}: {write_err}")
                        if transfer:
                            await transfer.fail(f"File write/processing error: {write_err}")
                        current_receiving_transfer = None
                else:
                    logger.warning(f"Received unexpected binary data from {display_name} when no transfer active or not in progress.")

            elif not is_binary:
                try:
                    data = json.loads(message)
                    msg_type = data.get("type")
                    logger.debug(f"Received JSON from {display_name}: type={msg_type}")

                    if msg_type == "MESSAGE":
                        try:
                            if "private_key" not in user_data or not isinstance(user_data["private_key"], rsa.RSAPrivateKey):
                                logger.error("Cannot decrypt message: Private key missing or invalid.")
                                await message_queue.put({"type":"log","message":f"[Decryption Error from {display_name}: Missing Key]","level":logging.ERROR})
                                continue

                            encrypted_hex = data.get("message", "")
                            if not encrypted_hex:
                                logger.warning(f"Received empty MESSAGE payload from {display_name}.")
                                continue

                            decrypted_bytes = user_data["private_key"].decrypt(
                                bytes.fromhex(encrypted_hex),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            decrypted_message = decrypted_bytes.decode('utf-8')
                            await message_queue.put({"type":"message", "sender_display_name":display_name, "content":decrypted_message})

                        except (ValueError, TypeError) as e:
                            logger.error(f"Decryption or decoding error for message from {display_name}: {e}")
                            await message_queue.put({"type":"log","message":f"[Decryption/Decoding Error from {display_name}]","level":logging.WARNING})
                        except Exception as dec_err:
                            logger.error(f"General decryption error for message from {display_name}: {dec_err}", exc_info=True)
                            await message_queue.put({"type":"log","message":f"[Decryption Error from {display_name}]","level":logging.WARNING})

                    elif msg_type == "file_transfer_init":
                        if current_receiving_transfer:
                            tid_new = data.get("transfer_id", "Unknown")
                            logger.warning(f"Received new transfer init {tid_new[:8]} from {display_name} while transfer {current_receiving_transfer.transfer_id[:8]} is active. Rejecting new request.")
                            continue

                        tid = data.get("transfer_id")
                        fname = data.get("filename")
                        fsize = data.get("filesize")
                        fhash = data.get("file_hash")

                        if not tid or not fname or fsize is None:
                             logger.error(f"Invalid file_transfer_init received from {display_name}: Missing fields. Data: {data}")
                             continue

                        is_valid, message_size_check = check_file_size(None, max_size_mb=2000, file_size_bytes=fsize)
                        if not is_valid:
                            logger.warning(f"Rejecting file from {display_name}: {message_size_check}")
                            continue

                        safe_fname = os.path.basename(fname)
                        try:
                            downloads_path = Path.home() / "Downloads"
                            p2p_downloads_path = downloads_path / "P2P Downloads"
                            p2p_downloads_path.mkdir(parents=True, exist_ok=True)
                            logger.info(f"Ensured download directory exists: {p2p_downloads_path}")
                        except Exception as dir_err:
                            logger.error(f"Could not create download directory {p2p_downloads_path}: {dir_err}. Falling back to relative 'downloads'.")
                            p2p_downloads_path = Path("downloads")
                            p2p_downloads_path.mkdir(exist_ok=True)

                        path_obj = p2p_downloads_path / safe_fname

                        has_space, space_message = check_disk_space(str(p2p_downloads_path), fsize / (1024 * 1024))
                        if not has_space:
                            logger.warning(f"Rejecting file from {display_name}: {space_message}")
                            continue

                        counter = 1
                        base, ext = path_obj.stem, path_obj.suffix
                        while path_obj.exists():
                            path_obj = p2p_downloads_path / f"{base}({counter}){ext}"
                            counter += 1
                        final_path_str = str(path_obj)

                        logger.info(f"Initiating receive for '{os.path.basename(final_path_str)}' ({tid[:8]}) from {display_name}, Size: {fsize} bytes. Saving to: {final_path_str}")
                        transfer = FileTransfer(final_path_str, peer_ip, "receive", tid)
                        transfer.total_size = int(fsize); transfer.expected_hash = fhash
                        transfer.state = TransferState.IN_PROGRESS

                        try:
                            transfer.file_handle = await aiofiles.open(final_path_str, "wb")

                            async with active_transfers_lock:
                                active_transfers[tid] = transfer

                            current_receiving_transfer = transfer

                            await message_queue.put({"type":"transfer_update"})
                            await message_queue.put({"type":"log", "message":f"Receiving '{os.path.basename(final_path_str)}' from {display_name} (ID: {tid[:8]})"})

                        except OSError as e:
                            logger.error(f"Failed to open file '{final_path_str}' for transfer {tid} from {display_name}: {e}")
                            await message_queue.put({"type":"log","message":f"Error receiving file from {display_name}: Cannot open destination file.","level":logging.ERROR})
                            current_receiving_transfer = None
                            async with active_transfers_lock:
                                active_transfers.pop(tid, None)

                    elif msg_type == "TRANSFER_PAUSE":
                        tid = data.get("transfer_id")
                        transfer = current_receiving_transfer
                        if transfer and transfer.transfer_id == tid:
                           async with transfer.condition:
                               if transfer.state == TransferState.IN_PROGRESS:
                                   logger.info(f"Received PAUSE request for active transfer {tid[:8]} from {display_name}. Pausing.")
                                   await transfer.pause()
                                   await message_queue.put({"type":"log","message":f"Transfer '{os.path.basename(transfer.file_path)}' paused by {display_name}."})
                               else:
                                   logger.warning(f"Received PAUSE for transfer {tid[:8]} from {display_name}, but current state is {transfer.state}.")
                        else:
                             logger.warning(f"Received PAUSE for irrelevant/unknown transfer {tid} from {display_name}. Current transfer: {getattr(current_receiving_transfer, 'transfer_id', 'None')}")

                    elif msg_type == "TRANSFER_RESUME":
                        tid = data.get("transfer_id")
                        transfer = current_receiving_transfer
                        if transfer and transfer.transfer_id == tid:
                           async with transfer.condition:
                               if transfer.state == TransferState.PAUSED:
                                   logger.info(f"Received RESUME request for active transfer {tid[:8]} from {display_name}. Resuming.")
                                   await transfer.resume()
                                   await message_queue.put({"type":"log","message":f"Transfer '{os.path.basename(transfer.file_path)}' resumed by {display_name}."})
                               else:
                                   logger.warning(f"Received RESUME for transfer {tid[:8]} from {display_name}, but current state is {transfer.state}.")
                        else:
                             logger.warning(f"Received RESUME for irrelevant/unknown transfer {tid} from {display_name}. Current transfer: {getattr(current_receiving_transfer, 'transfer_id', 'None')}")

                    elif msg_type == "GROUP_CREATE":
                        gn = data.get("groupname"); admin_ip = data.get("admin_ip")
                        if gn and admin_ip:
                            async with groups_lock: groups[gn] = {"admin": admin_ip, "members": {admin_ip}}
                            await message_queue.put({"type":"group_list_update"})
                            admin_display_name = get_peer_display_name(admin_ip)
                            await message_queue.put({"type":"log","message":f"Group '{gn}' created by {admin_display_name}"})
                        else: logger.warning(f"Received incomplete GROUP_CREATE from {display_name}: {data}")

                    elif msg_type == "GROUP_INVITE":
                        invite_data = data
                        if invite_data.get("groupname") and invite_data.get("inviter_ip"):
                            async with pending_lock: pending_invites.append(invite_data)
                            await message_queue.put({"type":"pending_invites_update"})
                            inviter_display_name = get_peer_display_name(invite_data['inviter_ip'])
                            await message_queue.put({"type":"log","message":f"Invite to join group '{invite_data['groupname']}' received from {inviter_display_name}"})
                        else: logger.warning(f"Received incomplete GROUP_INVITE from {display_name}: {data}")

                    elif msg_type == "GROUP_INVITE_RESPONSE":
                         gn=data.get("groupname"); invitee_ip=data.get("invitee_ip"); accepted=data.get("accepted")
                         own_ip = await get_own_ip()
                         if not gn or not invitee_ip or accepted is None:
                             logger.warning(f"Received incomplete GROUP_INVITE_RESPONSE from {display_name}: {data}"); continue

                         needs_update = False
                         log_msg = ""
                         members_list_for_update = None
                         group_info = None

                         async with groups_lock:
                             group_info = groups.get(gn)
                             if group_info and group_info.get("admin") == own_ip:
                                  invitee_display_name = get_peer_display_name(invitee_ip)
                                  if accepted:
                                      if invitee_ip not in group_info["members"]:
                                          group_info["members"].add(invitee_ip)
                                          needs_update = True
                                          log_msg = f"{invitee_display_name} accepted invite and joined '{gn}'."
                                          members_list_for_update = list(group_info["members"])
                                      else:
                                          needs_update = False
                                          log_msg = f"{invitee_display_name} accepted invite to '{gn}' (already a member)."
                                  else:
                                      needs_update = False
                                      log_msg = f"{invitee_display_name} declined invite to '{gn}'."

                         if needs_update and members_list_for_update:
                             await send_group_update_message(gn, members_list_for_update)
                             await message_queue.put({"type":"group_list_update"})

                         if log_msg:
                            await message_queue.put({"type":"log","message":log_msg})

                         if not group_info or (group_info and group_info.get("admin") != own_ip):
                             logger.warning(f"Received invite response for group '{gn}' but not admin or group doesn't exist.")


                    elif msg_type == "GROUP_JOIN_REQUEST":
                         gn=data.get("groupname"); req_ip=data.get("requester_ip"); req_uname=data.get("requester_username")
                         own_ip = await get_own_ip()
                         if not gn or not req_ip or not req_uname:
                              logger.warning(f"Received incomplete GROUP_JOIN_REQUEST from {display_name}: {data}"); continue

                         group_info = None
                         async with groups_lock: group_info = groups.get(gn)

                         if group_info and group_info.get("admin") == own_ip:
                              notify_ui = False
                              async with pending_lock:
                                   join_req_list = pending_join_requests.setdefault(gn, [])
                                   if not any(r.get("requester_ip") == req_ip for r in join_req_list):
                                        join_req_list.append({"requester_ip":req_ip,"requester_username":req_uname})
                                        notify_ui = True
                                   else: logger.info(f"Duplicate join request ignored for group '{gn}' from {req_uname}")

                              if notify_ui:
                                   await message_queue.put({"type":"join_requests_update"})
                                   await message_queue.put({"type":"log","message":f"Received join request for group '{gn}' from {req_uname}"})
                         else: logger.warning(f"Received join request for group '{gn}' but not admin or group doesn't exist.")

                    elif msg_type == "GROUP_JOIN_RESPONSE":
                         gn=data.get("groupname"); req_ip=data.get("requester_ip"); approved=data.get("approved"); admin_ip=data.get("admin_ip")
                         own_ip = await get_own_ip()
                         if not gn or not req_ip or approved is None or not admin_ip:
                              logger.warning(f"Received incomplete GROUP_JOIN_RESPONSE from {display_name}: {data}"); continue

                         if req_ip == own_ip:
                              admin_display_name = get_peer_display_name(admin_ip)
                              if approved:
                                   async with groups_lock:
                                       groups[gn] = {"admin":admin_ip,"members":{admin_ip, req_ip}}
                                   await message_queue.put({"type":"group_list_update"})
                                   await message_queue.put({"type":"log","message":f"Your join request for group '{gn}' was approved by {admin_display_name}."})
                              else:
                                   await message_queue.put({"type":"log","message":f"Your join request for group '{gn}' was denied by {admin_display_name}."})

                    elif msg_type == "GROUP_UPDATE":
                         gn=data.get("groupname"); members_set=set(data.get("members", [])); admin=data.get("admin")
                         own_ip = await get_own_ip()
                         if not gn or not members_set or not admin:
                              logger.warning(f"Received incomplete GROUP_UPDATE from {display_name}: {data}"); continue

                         needs_ui_update = False
                         log_msg = None

                         async with groups_lock:
                              current_group_info = groups.get(gn)
                              am_i_member = own_ip in members_set

                              if am_i_member:
                                   if not current_group_info or current_group_info.get("members") != members_set or current_group_info.get("admin") != admin:
                                        groups[gn] = {"admin": admin, "members": members_set}
                                        needs_ui_update = True
                                        log_msg = f"Group '{gn}' membership or admin updated."
                              elif current_group_info:
                                   del groups[gn]
                                   needs_ui_update = True
                                   log_msg = f"You were removed from group '{gn}'."

                         if needs_ui_update:
                              await message_queue.put({"type":"group_list_update"})
                              if log_msg: await message_queue.put({"type":"log","message":log_msg})

                    else:
                        logger.warning(f"Received unknown JSON message type '{msg_type}' from {display_name}")

                except json.JSONDecodeError:
                    logger.warning(f"Received non-JSON text message from {display_name}: {message[:100]}...")
                except Exception as proc_err:
                    logger.exception(f"Error processing JSON message type '{data.get('type', 'Unknown')}' from {display_name}: {proc_err}")

    except websockets.exceptions.ConnectionClosedOK:
        logger.info(f"Connection closed normally by {display_name} ({peer_ip})")
    except websockets.exceptions.ConnectionClosedError as e:
        logger.warning(f"Connection closed abruptly by {display_name} ({peer_ip}): {e}")
    except asyncio.CancelledError:
        logger.info(f"Message receive loop cancelled for {display_name} ({peer_ip})")
    except Exception as e:
        logger.exception(f"Unexpected error in message receive loop for {display_name} ({peer_ip}): {e}")
    finally:
        logger.debug(f"Cleaning up connection state for {peer_ip} in receive_peer_messages finally block.")

        if current_receiving_transfer:
            transfer_id_fail = current_receiving_transfer.transfer_id
            file_path_fail = current_receiving_transfer.file_path
            logger.warning(f"Failing active receiving transfer {transfer_id_fail[:8]} ({os.path.basename(file_path_fail)}) due to connection termination with {display_name}.")
            try:
                await current_receiving_transfer.fail("Connection lost during transfer")
                logger.info(f"Successfully failed and initiated cleanup for receiving transfer {transfer_id_fail[:8]}.")
            except Exception as fail_err:
                 logger.error(f"Error explicitly failing receiving transfer {transfer_id_fail[:8]} in finally block: {fail_err}", exc_info=True)
            current_receiving_transfer = None
        else:
             logger.debug(f"No active receiving transfer found for {peer_ip} during cleanup.")

        async with connections_lock:
            connections.pop(peer_ip, None)
        async with peer_data_lock:
            peer_public_keys.pop(peer_ip, None)
            peer_device_ids.pop(peer_ip, None)
            username = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
            if username: peer_usernames.pop(username, None)

        async with active_transfers_lock:
            outgoing_transfers_by_peer.pop(peer_ip, None)
            logger.debug(f"Cleared outgoing transfer tracking for {peer_ip} in finally block.")

        if not shutdown_event.is_set():
            await message_queue.put({"type": "connection_status", "peer_ip": peer_ip, "connected": False})
            final_display_name = get_peer_display_name(peer_ip)
            await message_queue.put({"type": "log", "message": f"Disconnected from {final_display_name}"})

        logger.info(f"Message receive loop finished for {display_name} ({peer_ip})")


async def maintain_peer_list(discovery_instance):
    while not shutdown_event.is_set():
        try:
            disconnected_peers = []
            async with connections_lock:
                current_connections = list(connections.items())

            for peer_ip, ws in current_connections:
                if shutdown_event.is_set(): break
                display_name = get_peer_display_name(peer_ip)

                try:
                    await asyncio.wait_for(ws.ping(), timeout=10.0)
                except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed, websockets.exceptions.WebSocketException) as e:
                    logger.warning(f"Connection lost or ping failed for {display_name} ({peer_ip}): {type(e).__name__}")
                    disconnected_peers.append(peer_ip)

                    if ws.state == State.OPEN:
                        try:
                            await asyncio.wait_for(ws.close(code=1011, reason="Ping failure or connection lost"), timeout=2.0)
                        except: pass

                    async with connections_lock: connections.pop(peer_ip, None)
                    async with peer_data_lock:
                        peer_public_keys.pop(peer_ip, None)
                        peer_device_ids.pop(peer_ip, None)
                        uname = next((u for u, ip in peer_usernames.items() if ip == peer_ip), None)
                        if uname: peer_usernames.pop(uname, None)
                    async with active_transfers_lock:
                         outgoing_transfers_by_peer.pop(peer_ip, None)

            if disconnected_peers:
                logger.info(f"Detected {len(disconnected_peers)} disconnected peers in maintain cycle.")
                for peer_ip in disconnected_peers:
                     display_name_disc = get_peer_display_name(peer_ip)
                     await message_queue.put({"type": "connection_status", "peer_ip": peer_ip, "connected": False})
                     await message_queue.put({"type": "log", "message": f"Lost connection to {display_name_disc}"})

            await asyncio.sleep(15)

        except asyncio.CancelledError:
            logger.info("maintain_peer_list task cancelled.")
            break
        except Exception as e:
            logger.exception(f"Error in maintain_peer_list loop: {e}")
            await asyncio.sleep(30)

    logger.info("maintain_peer_list stopped.")


async def user_input(discovery):
    pass

async def display_messages():
    pass
