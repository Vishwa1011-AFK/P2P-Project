import socket
import asyncio
import logging

logger = logging.getLogger(__name__)

async def get_own_ip():
    """
    Get the local IP address used for outbound connections (best effort).
    Connects to a public DNS server (doesn't send data) to determine the
    interface used for default route.
    """
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False) # Use non-blocking socket with asyncio
    try:
        # Use loop.sock_connect for non-blocking connect
        await loop.sock_connect(sock, ("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        logger.debug(f"Determined own IP via outgoing socket: {ip}")
        return ip
    except OSError as e:
        # Handle cases where the network might be unreachable or socket fails
        logger.warning(f"Could not determine own IP using UDP socket: {e}. Falling back.")
        # Fallback: Try getting hostname and resolving it
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip != "127.0.0.1":
                 logger.debug(f"Determined own IP via hostname resolution: {ip}")
                 return ip
        except socket.gaierror:
             logger.warning("Could not resolve hostname to IP. Using 127.0.0.1.")
        return "127.0.0.1" # Final fallback
    except Exception as e:
        logger.error(f"Unexpected error getting own IP: {e}", exc_info=True)
        return "127.0.0.1" # Final fallback
    finally:
        sock.close()