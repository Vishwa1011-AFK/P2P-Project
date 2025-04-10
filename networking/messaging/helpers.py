import logging
from networking.shared_state import connections, user_data, peer_usernames, peer_device_ids, username_to_ip
from networking.utils import get_own_ip as network_get_own_ip

def get_peer_display_name(peer_ip):
    """Gets the formatted display name (user(deviceID) or user) for a peer IP."""
    if not peer_ip:
        return "unknown_peer"

    # Check connected peers first for most reliable info
    original_username = get_peer_original_username(peer_ip)
    device_id = peer_device_ids.get(peer_ip)

    if original_username and device_id:
         # Check if multiple devices use the same original_username among *connected* peers
         username_count = sum(1 for ip in connections if get_peer_original_username(ip) == original_username)
         # Always show device ID if count > 1 or if the username itself is ambiguous or default
         # Or, maybe simpler: always show device ID for now for clarity? Let's try always showing it.
         # if username_count > 1 or original_username == "unknown":
         return f"{original_username}({device_id[:8]})"
         # else:
         #     return original_username # Return just username if unique among connected

    # Fallback if not fully connected/info missing - Check username_to_ip mapping
    display_name_from_map = next((dname for dname, ip in username_to_ip.items() if ip == peer_ip), None)
    if display_name_from_map:
         return display_name_from_map # Already formatted

    # Fallback to original username if known, even without device ID
    if original_username:
        return original_username # Might lack device ID

    # Very basic fallback
    logging.debug(f"Could not determine full display name for IP: {peer_ip}")
    return f"peer({peer_ip})"


def get_peer_original_username(peer_ip):
    """Gets the original username associated with a peer IP, if known."""
    # Primarily relies on the mapping established during HELLO
    return next((uname for uname, ip in peer_usernames.items() if ip == peer_ip), None)


def get_own_display_name():
    """Gets the display name for the current user."""
    username = user_data.get("original_username", "Me")
    device_id = user_data.get("device_id")
    return f"{username}({device_id[:8]})" if device_id else username

async def get_own_ip():
    """Async wrapper to get own IP."""
    return await network_get_own_ip()