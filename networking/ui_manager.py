import asyncio
import logging
import os
import sys # For stderr fallback

# Import prompt_toolkit components
try:
    from prompt_toolkit import Application
    from prompt_toolkit.layout import Layout, HSplit, Window
    from prompt_toolkit.widgets import TextArea
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.application.current import get_app
    # Optional: For potential future styling or formatted text
    # from prompt_toolkit.formatted_text import FormattedText
    # from prompt_toolkit.document import Document
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    # Define dummy classes or functions if needed for basic fallback (optional)
    print("[ERROR] prompt_toolkit not found. TUI will not be available.", file=sys.stderr)
    # A full fallback to basic input()/print() would require more significant changes

from .shared_state import shutdown_event

logger = logging.getLogger(__name__)

# --- Dynamic Completer (Requires prompt_toolkit) ---
if PROMPT_TOOLKIT_AVAILABLE:
    class DynamicCompleter(Completer):
        # Base commands and commands requiring path completion
        base_commands = [
            "/connect", "/disconnect", "/msg", "/send", "/sendfolder",
            "/pause", "/resume", "/transfers", "/list", "/changename",
            "/exit", "/help", "yes", "no"
        ]
        path_commands = ["/send", "/sendfolder"]
        peer_commands = ["/connect", "/disconnect", "/msg", "/send", "/sendfolder"]
        transfer_id_commands = ["/pause", "/resume"]

        def __init__(self, peer_manager, transfer_manager, config_manager):
            """
            Initializes the completer with access to managers.
            Args:
                peer_manager: Instance of PeerManager.
                transfer_manager: Instance of TransferManager.
                config_manager: Instance of ConfigManager.
            """
            self.peer_manager = peer_manager
            self.transfer_manager = transfer_manager
            self.config_manager = config_manager

        def get_completions(self, document, complete_event):
            """Generate completions based on the input text."""
            text = document.text_before_cursor
            word_before_cursor = document.get_word_before_cursor(WORD=True)
            parts = text.split()
            command = parts[0] if parts else ""

            try:
                # --- Complete Base Commands ---
                if not text or (len(parts) == 1 and not text.endswith(" ")):
                    for cmd in self.base_commands:
                        if cmd.startswith(word_before_cursor):
                            yield Completion(cmd, start_position=-len(word_before_cursor))

                # --- Complete Command Arguments ---
                elif command in self.peer_commands and len(parts) == 2 and not text.endswith(" "):
                     # Complete Peer Usernames for relevant commands
                     current_word = parts[1]
                     # Suggest connected peers first
                     connected_peers = self.peer_manager.get_all_connected_peers() # List of (uname, ip)
                     suggested_names = set()

                     for uname, _ in connected_peers:
                          if uname.startswith(current_word):
                               yield Completion(uname, start_position=-len(current_word))
                               suggested_names.add(uname)

                     # Then suggest discovered peers not yet connected
                     own_ip = self.config_manager.get_ip()
                     discovered = self.peer_manager.get_discovered_peers()
                     for ip, (uname, _) in discovered.items():
                         if ip != own_ip and uname not in suggested_names and uname.startswith(current_word):
                             yield Completion(uname, start_position=-len(current_word))
                             suggested_names.add(uname)

                elif command in self.path_commands and len(parts) >= 2 and (len(parts) > 2 or text.endswith(" ")):
                     # --- Basic Path Completion ---
                     # Path completion logic needs refinement, this is a simple start
                     path_text = text[len(command):].strip().split(" ", 1)[1] if len(parts) > 1 else ""
                     current_word = document.get_word_before_cursor(WORD=True) # Word being typed for path

                     # Determine base directory and fragment to complete
                     if os.sep in current_word or current_word.endswith(os.sep):
                          # Completing within a path or after a slash
                          basedir = os.path.dirname(path_text.rstrip(os.sep)) or '.'
                          fragment = "" # Complete all items in dir
                     else:
                          # Completing the first part of a path or a file/dir name
                          basedir = os.path.dirname(path_text) or '.'
                          fragment = os.path.basename(path_text)

                     basedir = os.path.expanduser(basedir) # Expand ~

                     try:
                          if os.path.isdir(basedir):
                               for name in os.listdir(basedir):
                                    if name.startswith(fragment) or not fragment:
                                         completion_text = name
                                         full_path = os.path.join(basedir, name)
                                         display_meta = 'Directory' if os.path.isdir(full_path) else 'File'
                                         # Add trailing slash for directory suggestion text
                                         if os.path.isdir(full_path):
                                              completion_text += os.sep

                                         yield Completion(
                                              completion_text,
                                              start_position=-len(fragment),
                                              display_meta=display_meta
                                         )
                     except OSError:
                          pass # Ignore errors listing directory (e.g., permissions)


                elif command in self.transfer_id_commands and len(parts) == 2 and not text.endswith(" "):
                     # Complete Transfer IDs
                     current_word = parts[1]
                     # Access active transfers via TransferManager
                     for tid in self.transfer_manager.get_active_transfer_ids(): # Need method in TransferManager
                         if tid.startswith(current_word):
                             yield Completion(tid, start_position=-len(current_word))

            except Exception as e:
                 # Log completion errors but don't crash the UI
                 logger.error(f"Error during completion generation: {e}", exc_info=True)

else:
    # Define a dummy completer if prompt_toolkit is not available
    class DynamicCompleter:
        def __init__(self, *args, **kwargs): pass
        def get_completions(self, document, complete_event): yield


class UIManager:
    """Manages the Text User Interface using prompt_toolkit."""

    def __init__(self, config_manager, peer_manager, transfer_manager, discovery_instance):
        """
        Initializes the UIManager.
        Args:
            config_manager: Instance of ConfigManager.
            peer_manager: Instance of PeerManager (can be None initially).
            transfer_manager: Instance of TransferManager (can be None initially).
            discovery_instance: Instance of PeerDiscovery.
        """
        if not PROMPT_TOOLKIT_AVAILABLE:
            logger.critical("prompt_toolkit is not installed. TUI cannot function.")
            # Decide how to handle this: raise error, run headless, etc.
            # For now, allow object creation but run_tui will fail.
            self._tui_available = False
        else:
             self._tui_available = True

        self.config_manager = config_manager
        self.peer_manager = peer_manager
        self.transfer_manager = transfer_manager
        self.discovery = discovery_instance # Needed for /changename -> broadcast

        self.message_queue = asyncio.Queue()

        # State for linking 'yes'/'no' input to the correct pending request context
        # Stores the relevant identifier (peer_ip or transfer_id) of the *last* displayed approval prompt
        self._pending_connection_approval_context = None
        self._pending_file_approval_context = None

        # Create TUI elements only if library is available
        if self._tui_available:
             self._create_tui_elements()
        else:
             self.tui_app = None
             self.output_area = None # Dummy object or None
             self.input_area = None

        logger.debug("UIManager initialized.")

    # Allow setting managers later if needed during setup sequence
    def set_peer_manager(self, manager):
        self.peer_manager = manager
        # Update completer if TUI exists
        if self._tui_available and self.input_area:
             self.input_area.completer.peer_manager = manager

    def set_transfer_manager(self, manager):
        self.transfer_manager = manager
        if self._tui_available and self.input_area:
            self.input_area.completer.transfer_manager = manager

    def _get_current_prompt(self):
        """Get the prompt string dynamically."""
        # Ensure config_manager is available
        username = self.config_manager.get_username() if self.config_manager else "User"
        return f"{username} > "

    def _create_tui_elements(self):
        """Create prompt_toolkit widgets and application."""
        logger.debug("Creating TUI elements.")
        try:
            self.output_area = TextArea(
                text="", read_only=True, scrollbar=True, line_numbers=False, focusable=False
            )
            # Pass managers to completer
            completer = DynamicCompleter(self.peer_manager, self.transfer_manager, self.config_manager)

            self.input_area = TextArea(
                height=1, prompt=self._get_current_prompt, multiline=False, wrap_lines=False,
                history=InMemoryHistory(),
                completer=completer,
                # When enter is pressed, exit the app.run_async() call with the input text
                accept_handler=lambda buff: get_app().exit(result=buff.text)
            )
            layout = Layout(
                HSplit([
                    self.output_area,
                    Window(height=1, char='-', style='class:separator'), # Separator line
                    self.input_area
                ])
            )
            # Define key bindings (Ctrl+C/D for exit)
            bindings = KeyBindings()
            @bindings.add("c-c", eager=True) # Eager to handle interrupt quickly
            @bindings.add("c-d", eager=True)
            def _(event):
                """ Control-C or Control-D triggers graceful shutdown signal. """
                logger.info("Ctrl+C/D detected, signaling shutdown.")
                event.app.exit(result="EXIT_APP_SIGNAL")

            self.tui_app = Application(
                layout=layout,
                key_bindings=bindings,
                full_screen=False, # Run inline in terminal
                mouse_support=True # Enable mouse support (e.g., for scrollbar)
            )
            logger.info("prompt_toolkit Application created.")
        except Exception as e:
             logger.critical("Failed to create TUI elements.", exc_info=True)
             print("[CRITICAL] Failed to initialize TUI elements. Check logs.", file=sys.stderr)
             self._tui_available = False # Mark TUI as unavailable


    async def add_message(self, message):
        """Add a message string or structured dict to the UI queue."""
        try:
            await self.message_queue.put(message)
        except Exception as e:
            logger.error(f"Failed to add message to UI queue: {e}")

    # --- Approval Request Handling ---

    async def request_connection_approval(self, peer_ip, requesting_username):
        """
        Displays a connection approval prompt and prepares for 'yes'/'no'.
        Returns the user's decision (True/False) or raises TimeoutError.
        """
        if not self._tui_available:
            logger.error("Cannot request connection approval: TUI not available.")
            # Default action in headless mode? Auto-deny for safety?
            return False # Auto-deny if no UI

        # Get the future from PeerManager
        approval_future = self.peer_manager.get_pending_connection_approval_future(peer_ip)
        if not approval_future:
             # This indicates a logic error - future should have been added before calling this
             logger.error(f"Logic Error: No pending connection future found for {peer_ip} when requesting UI approval.")
             return False # Cannot proceed

        # Queue UI message which will also set the context in _display_messages
        await self.add_message({
            "type": "ui_connection_approval_request",
            "peer_ip": peer_ip,
            "requesting_username": requesting_username
        })

        try:
            logger.debug(f"Waiting for user response (connection) for {peer_ip}")
            approved = await asyncio.wait_for(approval_future, timeout=70.0) # Allow time for user
            logger.debug(f"User response received for {peer_ip}: {approved}")
            return approved
        except asyncio.TimeoutError:
            logger.info(f"Connection approval for {requesting_username} ({peer_ip}) timed out.")
            await self.add_message(f"Approval request from {requesting_username} timed out.")
            # Ensure context is cleared if timeout happens
            if self._pending_connection_approval_context == peer_ip:
                 self._pending_connection_approval_context = None
            raise # Re-raise timeout for the caller (handle_incoming_connection) to handle
        except asyncio.CancelledError:
             logger.info(f"Connection approval wait cancelled for {peer_ip}")
             if self._pending_connection_approval_context == peer_ip:
                  self._pending_connection_approval_context = None
             raise # Re-raise cancellation

    async def request_file_approval(self, transfer_id, peer_username, relative_path, file_size):
        """
        Displays a file transfer approval prompt and prepares for 'yes'/'no'.
        UIManager is responsible for showing the prompt and setting internal context.
        It does NOT wait for the future here; TransferManager waits.
        """
        if not self._tui_available:
            logger.error("Cannot request file approval: TUI not available.")
            # Auto-deny in headless mode? TransferManager needs to handle future resolution.
            # We resolve it immediately here if no UI.
            if self.transfer_manager:
                 self.transfer_manager.resolve_pending_receive_approval(transfer_id, False)
            return # Don't queue UI message

        # Queue UI message. _display_messages will set the UI context.
        await self.add_message({
            "type": "ui_file_approval_request",
            "transfer_id": transfer_id,
            "peer_username": peer_username,
            "relative_path": relative_path,
            "file_size": file_size
        })
        logger.debug(f"File approval prompt queued for {transfer_id}")


    # --- TUI Update Logic ---

    def _update_output_sync(self, text_to_add, set_conn_context, set_file_context):
        """
        Synchronous part of UI update, intended to be called via event loop's
        call_soon_threadsafe from the _display_messages task.
        Updates the output area text and sets the internal approval context.
        """
        if not self._tui_available or not self.output_area:
            # Log to console if TUI isn't working
            print(text_to_add)
            return

        try:
            # --- Update Internal Approval Context ---
            # Clear previous context FIRST. Only one prompt should be active contextually.
            new_context_set = False
            if set_conn_context:
                self._pending_connection_approval_context = set_conn_context
                self._pending_file_approval_context = None # Clear other type
                logger.debug(f"UI Context set for Connection Approval: IP {set_conn_context}")
                new_context_set = True
            elif set_file_context:
                self._pending_file_approval_context = set_file_context
                self._pending_connection_approval_context = None # Clear other type
                logger.debug(f"UI Context set for File Approval: ID {set_file_context}")
                new_context_set = True

            # If this message wasn't an approval prompt, clear both contexts
            # This ensures 'yes'/'no' only applies immediately after a prompt.
            # EDIT: Reconsidered - maybe allow 'yes'/'no' for the last prompt even if other messages appeared?
            # Let's stick to clearing only if a *new* context is set. 'yes'/'no' handler will check if context exists.

            # --- Update Text Area ---
            current_text = self.output_area.text
            # Add newline if output doesn't end with one, unless it's empty
            prefix = "\n" if current_text and not current_text.endswith('\n') else ""
            new_full_text = current_text + prefix + text_to_add

            # Limit buffer lines to prevent excessive memory use
            max_lines = 1000 # Configurable?
            lines = new_full_text.split('\n')
            final_text = '\n'.join(lines[-max_lines:]) if len(lines) > max_lines else new_full_text

            # Assign directly to the widget's text attribute
            self.output_area.text = final_text

            # Optional: Attempt to scroll to bottom. Might not always work perfectly.
            # If scrolling is essential, more robust methods might be needed.
            # buffer = self.output_area.buffer
            # buffer.cursor_position = len(buffer.text)

        except Exception as update_err:
            # Log error but don't crash the display loop
            logger.exception(f"Error inside _update_output_sync: {update_err}")

    async def _display_messages(self):
        """Coroutine that reads from message_queue and schedules TUI updates."""
        logger.info("UI message display task started.")
        while not shutdown_event.is_set():
            try:
                # Wait for an item from the queue
                item = await self.message_queue.get()
                if shutdown_event.is_set(): # Check again after await
                    self.message_queue.task_done()
                    break

                display_text = ""
                conn_context_to_set = None # Peer IP
                file_context_to_set = None # Transfer ID

                # --- Format Message for Display ---
                if isinstance(item, dict):
                    msg_type = item.get("type")
                    # Handle specific structured messages (like approval requests)
                    if msg_type == "ui_file_approval_request":
                        file_context_to_set = item["transfer_id"] # Set context for this prompt
                        display_text = f"❓ File request from {item['peer_username']}: '{item['relative_path']}' ({item['file_size']} bytes). Accept? (yes/no)"
                    elif msg_type == "ui_connection_approval_request":
                        conn_context_to_set = item["peer_ip"] # Set context for this prompt
                        display_text = f"❓ Connection request from {item['requesting_username']} ({item['peer_ip']}). Accept? (yes/no)"
                    else:
                         # Default display for unknown dictionary types
                         display_text = f"[System Dict]: {item}"
                elif isinstance(item, str):
                    # Simple string message
                    display_text = item
                else:
                    # Handle other unexpected types in the queue
                    display_text = f"[System Unknown Type]: {type(item).__name__}"
                    logger.warning(f"Received unexpected item type in UI queue: {type(item).__name__}")

                # --- Schedule UI Update in Main Thread ---
                if self._tui_available and self.tui_app and self.tui_app.loop:
                     # Schedule the synchronous update function using the TUI app's loop
                     self.tui_app.loop.call_soon_threadsafe(
                         self._update_output_sync,
                         display_text,
                         conn_context_to_set,
                         file_context_to_set
                     )
                     # Schedule a redraw (invalidate)
                     self.tui_app.loop.call_soon_threadsafe(self.tui_app.invalidate)
                else:
                    # Fallback if TUI isn't running or available (e.g., early startup messages)
                    # Log directly to console
                    print(display_text)
                    # Optionally update self.output_area.text if it exists for initial state? Risky.

                # Mark the queue item as processed
                self.message_queue.task_done()

            except asyncio.CancelledError:
                logger.info("UI message display task cancelled.")
                break
            except Exception as e:
                logger.exception(f"Error in UI display_messages loop: {e}")
                # Avoid tight loop on error
                await asyncio.sleep(1)
        logger.info("UI message display task stopped.")

    # --- User Input Handling ---

    async def _handle_input(self, input_text):
        """Process user input commands received from the TUI."""
        if not input_text: return # Ignore empty input

        # Ensure managers are available before processing commands
        if not all([self.config_manager, self.peer_manager, self.transfer_manager]):
             logger.error("Managers not fully initialized in UIManager, cannot handle input.")
             await self.add_message("[ERROR] System not fully initialized.")
             return

        try:
            logger.debug(f"Handling user input: {input_text}")
            # --- Shutdown Command ---
            if input_text == "EXIT_APP_SIGNAL" or input_text == "/exit":
                await self.add_message("Shutdown initiated...")
                shutdown_event.set() # Signal all tasks to stop
                return # Stop processing further input

            # --- Help Command ---
            elif input_text == "/help":
                # Consider loading help text from a file or constant
                help_text = """
Available commands:
/connect <username>     - Connect to a discovered peer by username.
/disconnect <username>  - Disconnect from a connected peer.
/msg <username> <text>  - Send a private message to a connected peer.
/send <user> <path>     - Send a file to a connected peer.
/sendfolder <user> <path> - Send a folder to a connected peer.
/pause <transfer_id>    - Pause an ongoing file transfer.
/resume <transfer_id>   - Resume a paused file transfer.
/transfers              - List active file transfers.
/list                   - Show discovered and connected peers.
/changename <new_name>  - Change your username.
/exit                   - Exit the application.
/help                   - Show this help message.
yes / no                - Respond to the LATEST connection or file request prompt.
(Any other text)        - Send message to all connected peers (broadcast).
"""
                await self.add_message(help_text)

            # --- List Peers Command ---
            elif input_text == "/list":
                output = ["\n--- Peers ---"]
                # Connected Peers from PeerManager
                connected = self.peer_manager.get_all_connected_peers() # List of (uname, ip)
                if connected:
                     output.append("Connected:")
                     # Sort alphabetically by username for consistent display
                     for uname, ip in sorted(connected):
                          output.append(f"  - {uname} ({ip})")
                # Discovered Peers (via PeerManager's cache)
                discovered = self.peer_manager.get_discovered_peers()
                own_ip = self.config_manager.get_ip()
                # Filter out self and already connected peers
                discovered_only = []
                for ip, (uname, _) in discovered.items():
                    if ip != own_ip and not self.peer_manager.is_connected(peer_ip=ip):
                        discovered_only.append((uname, ip))

                if discovered_only:
                    output.append("Discovered (Not Connected):")
                    for uname, ip in sorted(discovered_only): # Sort discovered too
                        output.append(f"  - {uname} ({ip})")

                if len(output) == 1: # Only the header was added
                     output.append("No other peers found or connected.")
                await self.add_message("\n".join(output))


            # --- Connect Command ---
            elif input_text.startswith("/connect "):
                target_username = input_text[9:].strip()
                if not target_username:
                     await self.add_message("Usage: /connect <username>")
                     return

                # Check if already connected
                if self.peer_manager.is_connected(username=target_username):
                     await self.add_message(f"Already connected to {target_username}.")
                     return

                # Find IP in PeerManager's discovered list cache
                discovered_peers = self.peer_manager.get_discovered_peers()
                peer_ip = next((ip for ip, (uname, _) in discovered_peers.items() if uname == target_username), None)

                if not peer_ip:
                     await self.add_message(f"Peer '{target_username}' not found in discovered list. Use /list.")
                     return
                if peer_ip == self.config_manager.get_ip():
                     await self.add_message("Cannot connect to yourself.")
                     return

                # Import connect_to_peer here to avoid circular dependency at module level if needed
                # Or ensure it's imported in the module scope if structure allows
                from .connection import connect_to_peer # Assuming moved to connection.py
                # Start connection attempt in background, passing required managers
                logger.info(f"User initiated connect to {target_username} ({peer_ip})")
                asyncio.create_task(connect_to_peer(
                    peer_ip=peer_ip,
                    target_username=target_username, # Pass target name for handshake verification
                    config_manager=self.config_manager,
                    peer_manager=self.peer_manager,
                    ui_manager=self # Pass self (UIManager)
                ), name=f"Connect-{target_username}")
                # connect_to_peer function will handle UI messages for progress/success/failure

            # --- Disconnect Command ---
            elif input_text.startswith("/disconnect "):
                target_username = input_text[12:].strip()
                if not target_username:
                     await self.add_message("Usage: /disconnect <username>")
                     return
                # Get IP from PeerManager
                peer_ip = self.peer_manager.get_peer_ip(target_username)
                if not peer_ip:
                     await self.add_message(f"Not connected to a peer named '{target_username}'.")
                     return
                # Use PeerManager to handle disconnection and cleanup
                logger.info(f"User initiated disconnect from {target_username} ({peer_ip})")
                await self.peer_manager.remove_peer(peer_ip, "User disconnected command")
                # remove_peer handles the UI message

            # --- Send Private Message Command ---
            elif input_text.startswith("/msg "):
                parts = input_text[5:].split(" ", 1)
                if len(parts) < 2:
                    await self.add_message("Usage: /msg <username> <message>")
                    return
                target_username, msg_content = parts[0].strip(), parts[1]

                # Import send_message or use protocol module reference
                from .protocol import send_message # Assuming moved to protocol.py
                # Call send function, passing necessary managers
                logger.debug(f"User sending private message to {target_username}")
                if await send_message(target_username, msg_content, self.config_manager, self.peer_manager):
                     # Only log to UI if send was successful (send_message handles errors)
                     await self.add_message(f"Me → {target_username}: {msg_content}")
                # send_message function queues error messages to UI if needed

            # --- Send File / Folder Command ---
            elif input_text.startswith("/send ") or input_text.startswith("/sendfolder "):
                 is_folder = input_text.startswith("/sendfolder")
                 command_len = 12 if is_folder else 6
                 parts = input_text[command_len:].strip().split(" ", 1) # Split target user and path
                 if len(parts) < 2:
                     cmd_name = '/sendfolder' if is_folder else '/send'
                     item_type = 'folder' if is_folder else 'file'
                     await self.add_message(f"Usage: {cmd_name} <username> <path_to_{item_type}>")
                     return
                 target_username, item_path = parts[0].strip(), parts[1].strip()

                 if not target_username or not item_path:
                      cmd_name = '/sendfolder' if is_folder else '/send'
                      item_type = 'folder' if is_folder else 'file'
                      await self.add_message(f"Usage: {cmd_name} <username> <path_to_{item_type}>")
                      return

                 # Delegate the request to TransferManager
                 # TransferManager will handle path validation, peer checking, and task creation
                 logger.info(f"User initiated {'folder' if is_folder else 'file'} send to {target_username}: {item_path}")
                 await self.transfer_manager.request_send_item(target_username, item_path)
                 # TransferManager queues progress/error messages to UI


            # --- Pause / Resume Transfer Command ---
            elif input_text.startswith("/pause "):
                 transfer_id = input_text[7:].strip()
                 if not transfer_id:
                      await self.add_message("Usage: /pause <transfer_id>")
                 else:
                      logger.debug(f"User requested pause for transfer {transfer_id}")
                      await self.transfer_manager.pause_transfer(transfer_id)
                      # pause_transfer handles UI messages

            elif input_text.startswith("/resume "):
                 transfer_id = input_text[8:].strip()
                 if not transfer_id:
                      await self.add_message("Usage: /resume <transfer_id>")
                 else:
                      logger.debug(f"User requested resume for transfer {transfer_id}")
                      await self.transfer_manager.resume_transfer(transfer_id)
                      # resume_transfer handles UI messages

            # --- List Transfers Command ---
            elif input_text == "/transfers":
                 logger.debug("User requested list of transfers.")
                 transfer_list_lines = self.transfer_manager.get_active_transfers_info()
                 await self.add_message("\n".join(transfer_list_lines))

            # --- Change Name Command ---
            elif input_text.startswith("/changename "):
                new_username = input_text[12:].strip()
                if not new_username:
                    await self.add_message("Usage: /changename <new_username>")
                    return

                logger.info(f"User requested username change to: {new_username}")
                # Call ConfigManager to handle change, save, notify peers, and trigger broadcast
                success = await self.config_manager.change_username(
                    new_username,
                    self.discovery, # Pass discovery instance for broadcast
                    self.peer_manager # Pass peer manager for notification
                )
                if success:
                     # Update TUI prompt immediately (if TUI is running)
                     if self._tui_available and self.tui_app and self.input_area:
                          self.input_area.prompt = self._get_current_prompt # Reset prompt source
                          self.tui_app.invalidate() # Force redraw to show new prompt
                     logger.info("Username change successful.")
                else:
                     logger.error("Username change failed.")
                     # ConfigManager should have queued an error message


            # --- Yes / No Approval Input ---
            elif input_text.lower() == "yes" or input_text.lower() == "no":
                 is_yes = input_text.lower() == "yes"
                 logger.debug(f"User input 'yes'/'no': {is_yes}. Checking context.")
                 responded = False
                 # Check File context FIRST (as it might be more common/transient)
                 if self._pending_file_approval_context:
                      transfer_id = self._pending_file_approval_context
                      # Clear context immediately before resolving future
                      self._pending_file_approval_context = None
                      self._pending_connection_approval_context = None # Clear other just in case

                      logger.info(f"Applying user response '{is_yes}' to file transfer {transfer_id}")
                      # Resolve the future via TransferManager
                      if self.transfer_manager.resolve_pending_receive_approval(transfer_id, is_yes):
                           await self.add_message(f"Response '{input_text}' registered for file transfer.")
                           responded = True
                      else:
                           # Future might have already been resolved (e.g., timeout)
                           logger.warning(f"Failed to resolve file future for {transfer_id} with response '{is_yes}'. Might have timed out.")
                           await self.add_message(f"Could not apply response '{input_text}' to file request (possibly timed out).")

                 # Check Connection context if file context wasn't active
                 elif self._pending_connection_approval_context:
                      peer_ip = self._pending_connection_approval_context
                      # Clear context immediately
                      self._pending_connection_approval_context = None
                      self._pending_file_approval_context = None

                      logger.info(f"Applying user response '{is_yes}' to connection request from {peer_ip}")
                      # Resolve the future via PeerManager
                      if self.peer_manager.resolve_pending_connection_approval(peer_ip, is_yes):
                           await self.add_message(f"Response '{input_text}' registered for connection request.")
                           responded = True
                      else:
                           logger.warning(f"Failed to resolve connection future for {peer_ip} with response '{is_yes}'. Might have timed out.")
                           await self.add_message(f"Could not apply response '{input_text}' to connection request (possibly timed out).")

                 if not responded and not self._pending_file_approval_context and not self._pending_connection_approval_context:
                      # Only show "no pending request" if context was truly empty when 'yes/no' was entered
                       await self.add_message(f"'{input_text}' received, but no approval request is currently pending a response.")


            # --- Broadcast Message (Default for non-command input) ---
            elif not input_text.startswith("/"):
                 logger.debug("User sending broadcast message.")
                 # Import send_message or use protocol module reference
                 from .protocol import send_message # Assuming moved to protocol.py
                 # Send to all connected peers (target_username=None)
                 if await send_message(None, input_text, self.config_manager, self.peer_manager):
                      # Only log to self if send was successful to at least one peer
                      await self.add_message(f"Me (to all): {input_text}")
                 # send_message handles queuing errors if sending fails

            # --- Unknown Command ---
            else:
                 unknown_cmd = input_text.split()[0]
                 logger.warning(f"Unknown command entered: {unknown_cmd}")
                 await self.add_message(f"Unknown command: {unknown_cmd}. Type /help for options.")

        except asyncio.CancelledError:
            logger.info("Input handling cancelled.")
            raise # Propagate cancellation
        except Exception as e:
            # Catch-all for unexpected errors during command processing
            logger.exception(f"Error handling input '{input_text}': {e}")
            try:
                 # Try to inform the user via UI queue
                 await self.add_message(f"[ERROR] Failed to process command '{input_text.split()[0]}': {e}")
            except Exception as log_e:
                 # Fallback if queuing message fails
                 logger.error(f"Failed to queue error message after input handling error: {log_e}")
                 print(f"[ERROR] Failed to process command: {e}", file=sys.stderr)


    # --- TUI Runner ---
    async def run_tui(self, initial_messages=None):
        """Main coroutine to run the TUI application and handle input/output."""
        if not self._tui_available:
            logger.error("TUI cannot run because prompt_toolkit is not available or failed to initialize.")
            # Optionally run a basic non-TUI loop here for headless mode
            print("--- TUI Unavailable ---")
            print("Application running in basic mode. Type /exit to quit.")
            while not shutdown_event.is_set():
                try:
                    cmd = await asyncio.to_thread(input, f"{self._get_current_prompt()}")
                    await self._handle_input(cmd)
                except (EOFError, KeyboardInterrupt):
                    print("\nExiting...")
                    shutdown_event.set()
                except Exception as e:
                     print(f"[Input Error] {e}")
                     logger.error(f"Error in basic input loop: {e}")
                     await asyncio.sleep(1) # Prevent tight loop on continuous errors
            return # Exit if TUI not available

        logger.info("Starting TUI runner task.")

        # Set initial text in the output area
        if self.output_area and initial_messages:
            self.output_area.text = "\n".join(initial_messages)

        # Start the background task that displays messages from the queue
        display_task = asyncio.create_task(self._display_messages(), name="MessageDisplay")

        # --- Main TUI Interaction Loop ---
        try:
            while not shutdown_event.is_set():
                # Run the prompt_toolkit application asynchronously.
                # This waits for user input (Enter key or Ctrl+C/D).
                input_text = await self.tui_app.run_async()

                # run_async() returns the result passed to event.app.exit()
                # Check shutdown flag *after* await returns, as exit signal might set it
                if shutdown_event.is_set():
                     logger.debug("Shutdown event detected after TUI input/exit signal.")
                     break

                # If run_async returned normally (Enter pressed), process input
                await self._handle_input(input_text)

                # Check again if input handler triggered shutdown
                if shutdown_event.is_set():
                     logger.debug("Shutdown event set by input handler.")
                     break

        except asyncio.CancelledError:
             logger.info("TUI runner task cancelled.")
        except EOFError:
            # Should be handled by Ctrl+D binding now, but keep as fallback
            logger.info("EOF received in TUI, initiating shutdown.")
            if not shutdown_event.is_set(): # Avoid duplicate messages
                 await self.add_message("EOF received, shutting down...")
                 shutdown_event.set()
        except Exception as e:
             logger.critical(f"Critical error in TUI runner task: {e}", exc_info=True)
             # Try to log to UI queue before shutting down
             try: await self.add_message(f"[CRITICAL TUI ERROR] {e}. Shutting down.")
             except: pass # Ignore errors trying to log during critical failure
             shutdown_event.set() # Trigger shutdown on unexpected TUI errors
        finally:
            logger.info("Exiting TUI runner task and performing cleanup.")
            # 1. Ensure display task is cancelled and awaited briefly
            if display_task and not display_task.done():
                logger.debug("Cancelling display task.")
                display_task.cancel()
                try:
                    await asyncio.wait_for(display_task, timeout=1.0)
                    logger.debug("Display task finished cancellation.")
                except asyncio.CancelledError:
                    logger.debug("Display task already cancelled.")
                except asyncio.TimeoutError:
                    logger.warning("Timed out waiting for display task to cancel.")
                except Exception as ex:
                     logger.error(f"Error awaiting display task cancellation: {ex}")

            # 2. Ensure TUI application exits cleanly if it's somehow still marked as running
            #    (Should exit via event.app.exit(), but as safety)
            if self.tui_app and self.tui_app.is_running:
                 try:
                      logger.debug("Ensuring TUI application exit.")
                      self.tui_app.exit()
                 except Exception as app_exit_err:
                      # Log potential errors during final exit, but don't block shutdown
                      logger.debug(f"Exception during final tui_app.exit(): {app_exit_err}")
            logger.info("TUI runner task finished cleanup.")

    def stop(self):
        """ Signals the TUI task to stop gracefully. """
        logger.debug("UIManager stop called.")
        # TUI loop primarily checks shutdown_event, but explicitly exiting
        # the app can sometimes interrupt run_async() faster.
        if self._tui_available and self.tui_app and self.tui_app.is_running:
             try:
                 # Pass the specific exit signal our binding uses
                 self.tui_app.exit(result="EXIT_APP_SIGNAL")
             except Exception:
                  pass # Ignore errors during forced exit signalling


# Helper method for TransferManager completer
# Add this method to TransferManager class in transfer_manager.py
# def get_active_transfer_ids(self):
#     """Returns a list of active transfer IDs."""
#     return list(self._active_transfers.keys()