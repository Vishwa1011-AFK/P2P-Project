from networking.shared_state import connections, user_data, peer_usernames, peer_device_ids
from networking.utils import get_own_ip as network_get_own_ip

def get_peer_display_name(peer_ip):
    username = next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), "unknown")
    device_id = peer_device_ids.get(peer_ip, "unknown")
    device_suffix = f"({device_id[:8]})" if device_id != "unknown" else "(?)"
    username_count = sum(1 for ip in connections if get_peer_original_username(ip) == username)
    return f"{username}{device_suffix}" if username_count > 1 or username == "unknown" else username

def get_peer_original_username(peer_ip):
    return next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)

def get_own_display_name():
    username = user_data.get("original_username", "User")
    device_id = user_data.get("device_id")
    return f"{username}({device_id[:8]})" if device_id else username

async def get_own_ip():
    return await network_get_own_ip()