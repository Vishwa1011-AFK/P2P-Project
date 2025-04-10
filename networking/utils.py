import socket
import asyncio
import logging

# Cache the IP address to avoid frequent lookups
_ip_cache = None
_ip_cache_lock = asyncio.Lock()

async def get_own_ip():
    """Get the local IP address used for outbound connections, caching the result."""
    global _ip_cache
    async with _ip_cache_lock:
        if _ip_cache is not None:
            return _ip_cache

        loop = asyncio.get_running_loop()
        # Use a context for the socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                 # Don't require connection if possible, system might route differently.
                 # Connecting to a known external address helps find the default outbound IP.
                 sock.setblocking(False) # Necessary for run_in_executor with sockets? Maybe not.
                 await loop.run_in_executor(None, sock.connect, ("8.8.8.8", 80))
                 ip = sock.getsockname()[0]
                 _ip_cache = ip
                 logging.debug(f"Determined own IP: {ip}")
                 return ip
        except OSError as e:
             logging.warning(f"Could not connect to external host to determine IP: {e}. Falling back.")
             # Fallback strategy 1: Get hostname IP
             try:
                 hostname = socket.gethostname()
                 ip = socket.gethostbyname(hostname)
                 if not ip.startswith("127."):
                      _ip_cache = ip
                      logging.debug(f"Using hostname IP: {ip}")
                      return ip
             except socket.gaierror:
                  logging.warning("Could not resolve hostname IP.")
             # Fallback strategy 2: Return loopback (least ideal)
             logging.warning("Could not determine local IP. Using 127.0.0.1.")
             _ip_cache = "127.0.0.1"
             return "127.0.0.1"
        except Exception as e:
            logging.exception(f"Unexpected error getting own IP: {e}")
            _ip_cache = "127.0.0.1"
            return "127.0.0.1"

def reset_ip_cache():
     """Allows resetting the cached IP if network changes."""
     global _ip_cache
     # No lock needed here as it's just setting to None
     _ip_cache = None
     logging.info("Own IP cache reset.")