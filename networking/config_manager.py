import asyncio
import json
import logging
import os
import uuid
from appdirs import user_config_dir
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from .utils import get_own_ip  # Assuming utils.py exists in the same directory

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, ui_manager_queue=None):
        """
        Initializes the ConfigManager.
        Args:
            ui_manager_queue: An asyncio.Queue to send messages (like startup/errors) to the UI.
                              Can be None during initial setup, but should be set later.
        """
        self.user_data = {}
        self._config_dir = self._get_config_directory()
        self._config_file_path = os.path.join(self._config_dir, "user_config.json")
        self._ui_queue = ui_manager_queue # To queue startup/error messages
        logger.debug(f"Config directory: {self._config_dir}")
        logger.debug(f"Config file path: {self._config_file_path}")

    def _get_config_directory(self):
        """Determine the appropriate config directory based on the OS."""
        appname = "P2PChat"
        appauthor = "P2PAppAuthor" # Providing an author string is recommended by appdirs
        config_dir = user_config_dir(appname, appauthor)
        try:
            os.makedirs(config_dir, exist_ok=True)
        except OSError as e:
            # Handle potential permission errors during directory creation
            logger.critical(f"Failed to create config directory {config_dir}: {e}", exc_info=True)
            # Depending on the severity, you might want to raise an exception or exit
            # For now, log critical error and proceed, hoping file operations fail later if needed
            print(f"[CRITICAL] Failed to create config directory: {e}", file=sys.stderr)
        return config_dir

    async def _queue_message(self, message):
        """Helper to queue messages for the UI Manager."""
        if self._ui_queue:
            try:
                await self._ui_queue.put(message)
            except Exception as e:
                logger.error(f"Failed to queue message: {e}")
                # Fallback print if queue fails unexpectedly
                print(f"[Queue Error] {message}")
        else:
            # Fallback if queue not available during early init
            print(message)

    async def initialize(self):
        """Load or create user configuration. Returns True on success, False on critical failure."""
        try:
            own_ip = await get_own_ip()
            self.user_data['ip'] = own_ip # Store own IP early
            logger.info(f"Device IP identified as: {own_ip}")
        except Exception as e:
            logger.error(f"Failed to get own IP address: {e}", exc_info=True)
            await self._queue_message("[WARNING] Could not determine local IP address.")
            self.user_data['ip'] = "127.0.0.1" # Fallback IP


        if os.path.exists(self._config_file_path):
            logger.info(f"Config file found at {self._config_file_path}. Attempting to load.")
            try:
                with open(self._config_file_path, "r", encoding='utf-8') as f:
                    loaded_data = json.load(f)

                # Basic validation of loaded data
                required_keys = ["original_username", "internal_username", "public_key", "private_key", "device_id"]
                if not all(key in loaded_data for key in required_keys):
                    raise ValueError("Config file missing required keys.")

                self.user_data.update(loaded_data)
                # Deserialize keys
                self.user_data["public_key"] = serialization.load_pem_public_key(
                    self.user_data["public_key"].encode('utf-8')
                )
                self.user_data["private_key"] = serialization.load_pem_private_key(
                    self.user_data["private_key"].encode('utf-8'), password=None
                )
                await self._queue_message(f"Config loaded. Welcome back, {self.get_username()}!")
                logger.info("User configuration loaded successfully.")
                return True
            except (json.JSONDecodeError, ValueError, KeyError, TypeError, FileNotFoundError) as e:
                logger.exception(f"Error loading or parsing config file: {e}. Creating a new one.")
                await self._queue_message(f"[ERROR] Invalid config file: {e}. Creating a new one.")
                # Fall through to create new config if loading fails badly
            except Exception as e:
                logger.exception(f"Unexpected error loading config: {e}. Creating a new one.")
                await self._queue_message(f"[ERROR] Unexpected error loading config: {e}. Creating a new one.")
                # Fall through
        else:
             logger.info("No config file found. Prompting for username.")

        # --- Create New Config ---
        try:
            # Use aioconsole ONLY if config doesn't exist or is invalid
            # Defer import to avoid making it a hard dependency if config exists
            try:
                 from aioconsole import ainput # Local import only when needed
            except ImportError:
                 logger.critical("aioconsole package not found. Cannot prompt for username. Please install requirements.")
                 await self._queue_message("[CRITICAL] Required package 'aioconsole' not found. Cannot continue setup.")
                 return False # Indicate fatal error

            initial_username = await ainput("Enter your desired username: ")
            if not initial_username or initial_username.isspace():
                await self._queue_message("[CRITICAL] Username cannot be empty. Exiting.")
                logger.critical("Username input was empty during initial setup.")
                return False # Indicate fatal error

            await self._create_new_user_config(initial_username.strip()) # Strip whitespace
            await self._queue_message(f"New config created. Welcome, {self.get_username()}")
            return True
        except Exception as e:
            logger.exception(f"Failed to create new user config during initialization: {e}")
            await self._queue_message(f"[CRITICAL] Failed to setup user configuration: {e}. Exiting.")
            return False # Indicate fatal error

    async def _create_new_user_config(self, username):
        """Create and save a new user configuration."""
        if not username:
            raise ValueError("Username cannot be empty.")

        logger.info(f"Creating new user config for username: {username}")
        original_username = username
        # Internal username might not be strictly necessary anymore if device_id is used
        # but keep for potential future internal tracking.
        internal_username = f"{original_username}_{uuid.uuid4()}"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        device_id = str(uuid.uuid4()) # Unique ID for this installation

        # Update internal state
        self.user_data.clear()
        current_ip = self.user_data.get('ip', await get_own_ip()) # Preserve IP if already found
        self.user_data.update({
            "original_username": original_username,
            "internal_username": internal_username,
            "public_key": public_key,
            "private_key": private_key,
            "device_id": device_id,
            "ip": current_ip # Ensure IP is stored
        })

        # Prepare data for saving
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # WARNING: Private key stored unencrypted
        ).decode('utf-8')

        config_data_to_save = {
            "original_username": original_username,
            "internal_username": internal_username,
            "public_key": public_key_pem,
            "private_key": private_key_pem, # Consider encrypting this in a real app
            "device_id": device_id
        }

        # Save to file
        try:
            with open(self._config_file_path, "w", encoding='utf-8') as f:
                json.dump(config_data_to_save, f, indent=4)
            logger.info(f"New user config saved to {self._config_file_path}")
        except Exception as e:
            logger.exception(f"Failed to save user config to {self._config_file_path}: {e}")
            await self._queue_message(f"[ERROR] Failed to save configuration: {e}")
            # Should this re-raise or just log? Re-raising might stop the app, which could be desired.
            raise # Re-raise the exception to indicate failure to the caller (initialize)

    async def change_username(self, new_username, discovery_instance, peer_manager):
        """Update the username in config, notify peers, and trigger broadcast."""
        new_username = new_username.strip() # Clean input
        if not new_username or new_username.isspace():
            await self._queue_message("Username cannot be empty.")
            return False
        if new_username == self.get_username():
            await self._queue_message("New username is the same as the current one.")
            return False

        old_username = self.get_username()
        logger.info(f"Attempting to change username from '{old_username}' to '{new_username}'")

        try:
            # Update in-memory data first
            self.user_data['original_username'] = new_username

            # Resave the config file with the updated username
            # Ensure keys are serialized correctly for JSON
            public_key_pem = self.user_data['public_key'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            private_key_pem = self.user_data['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            config_data_to_save = {
                "original_username": new_username,
                "internal_username": self.user_data['internal_username'], # Keep internal
                "public_key": public_key_pem,
                "private_key": private_key_pem,
                "device_id": self.user_data['device_id'] # Keep device ID
            }

            with open(self._config_file_path, "w", encoding='utf-8') as f:
                json.dump(config_data_to_save, f, indent=4)

            await self._queue_message(f"Username changed to '{new_username}'.")
            logger.info(f"Username updated in config file.")

            # Notify connected peers (using PeerManager)
            if peer_manager:
                await peer_manager.notify_username_change(old_username, new_username)
            else:
                logger.warning("PeerManager not available, cannot notify connected peers of username change.")


            # Send immediate broadcast (using Discovery)
            if discovery_instance:
                 logger.info("Sending immediate broadcast for username change.")
                 # Pass self (ConfigManager instance) to the broadcast function
                 await discovery_instance.send_immediate_broadcast(self)
            else:
                 logger.warning("Discovery instance not available, cannot send immediate broadcast.")

            return True

        except Exception as e:
            logger.exception("Failed to save config or notify during username change.")
            await self._queue_message(f"[ERROR] Failed to change username: {e}")
            # Revert change in memory if save/notify failed
            self.user_data['original_username'] = old_username
            return False

    # --- Getters ---
    def get_username(self):
        return self.user_data.get("original_username", "UnknownUser")

    def get_internal_username(self):
        return self.user_data.get("internal_username", "UnknownInternal")

    def get_public_key(self):
        return self.user_data.get("public_key")

    def get_private_key(self):
        # Accessing the private key should be done cautiously.
        # Consider if this needs to be exposed directly or if methods using it are sufficient.
        return self.user_data.get("private_key")

    def get_public_key_pem(self):
        key = self.get_public_key()
        if key:
            try:
                return key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            except Exception as e:
                logger.error(f"Failed to serialize public key to PEM: {e}")
        return None

    def get_device_id(self):
        return self.user_data.get("device_id")

    def get_ip(self):
        return self.user_data.get("ip", "127.0.0.1") # Return fallback if not set

    def set_ui_queue(self, queue):
        """Allows setting the UI queue after initial instantiation if needed."""
        logger.debug("UI message queue being set/updated in ConfigManager.")
        self._ui_queue = queue