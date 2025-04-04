import socket
import asyncio

async def get_own_ip():
    """Get the local IP address using multiple fallback strategies."""
    loop = asyncio.get_event_loop()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        await loop.run_in_executor(None, sock.connect, ("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception as e:
        logging.debug(f"Strategy 1 (DNS connect) failed: {e}")
    
    try:
        for interface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for address in addresses[netifaces.AF_INET]:
                    ip = address.get('addr')
                    if ip and not ip.startswith('127.'):
                        return ip
    except Exception as e:
        logging.debug(f"Strategy 2 (interface scan) failed: {e}")
    
    logging.warning("Could not determine external IP, using localhost")
    return "127.0.0.1"