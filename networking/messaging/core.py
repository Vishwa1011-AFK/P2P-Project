async def handle_incoming_connection(websocket, peer_ip):
    """Handle a new incoming WebSocket connection from a peer."""
    try:
        # Get own IP to check against peer_ip
        own_ip = await get_own_ip()
        if peer_ip == own_ip:
            await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": "Cannot connect to self"}))
            await websocket.close(code=1008, reason="Self-connection rejected")
            await message_queue.put("Rejected connection attempt from self.")
            return False

        message = await websocket.recv()
        if shutdown_event.is_set():
            await websocket.close(code=1001, reason="Server shutting down")
            return False

        if message.startswith("INIT "):
            _, sender_ip = message.split(" ", 1)
            if peer_ip in connections:
                await websocket.close(code=1008, reason="Already connected")
                return False

            await websocket.send("INIT_ACK")
            request_message = await websocket.recv()
            request_data = json.loads(request_message)

            if request_data["type"] == "CONNECTION_REQUEST":
                requesting_username = request_data["requesting_username"]
                requesting_device_id = request_data["device_id"]
                target_username = request_data["target_username"]
                peer_key_pem = request_data["key"]

                requesting_display_name = f"{requesting_username}({requesting_device_id[:8]})"

                if target_username != user_data["original_username"]:
                    await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": "Incorrect target username"}))
                    await websocket.close()
                    return False

                denial_count = connection_denials.get(target_username, {}).get(requesting_username, 0)
                if denial_count >= 3:
                    await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": False, "reason": "Connection blocked"}))
                    await websocket.close()
                    return False

                approval_future = asyncio.Future()
                pending_approvals[(peer_ip, requesting_username)] = approval_future
                await message_queue.put({
                    "type": "approval_request",
                    "peer_ip": peer_ip,
                    "requesting_username": requesting_display_name
                })

                approved = False
                try:
                    approved = await asyncio.wait_for(approval_future, timeout=30.0)
                except asyncio.TimeoutError:
                    await message_queue.put(f"\nApproval request for {requesting_display_name} timed out.")
                finally:
                    if (peer_ip, requesting_username) in pending_approvals:
                        del pending_approvals[(peer_ip, requesting_username)]

                if not approved:
                    if target_username not in connection_denials:
                        connection_denials[target_username] = {}
                    current_denials = connection_denials[target_username]
                    current_denials[requesting_username] = current_denials.get(requesting_username, 0) + 1
                    await message_queue.put(f"Denied connection from {requesting_display_name} ({current_denials[requesting_username]}/3)")
                    if current_denials[requesting_username] >= 3:
                        await message_queue.put(f"{requesting_display_name} has been blocked for this session.")

                await websocket.send(json.dumps({"type": "CONNECTION_RESPONSE", "approved": approved}))

                if not approved:
                    await websocket.close()
                    return False

                own_public_key_pem = user_data["public_key"].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                await websocket.send(json.dumps({
                    "type": "IDENTITY",
                    "username": user_data["original_username"],
                    "device_id": user_data["device_id"],
                    "key": own_public_key_pem
                }))

                identity_message = await websocket.recv()
                identity_data = json.loads(identity_message)
                if identity_data["type"] == "IDENTITY":
                    peer_public_keys[peer_ip] = serialization.load_pem_public_key(peer_key_pem.encode())
                    peer_usernames[requesting_username] = peer_ip
                    peer_device_ids[peer_ip] = requesting_device_id
                    connections[peer_ip] = websocket
                    display_name = get_peer_display_name(peer_ip)
                    await message_queue.put(f"Accepted connection from {display_name}")
                    return True
                else:
                    await websocket.close(code=1002, reason="Unexpected message type")
                    return False
            else:
                await websocket.close(code=1002, reason="Unexpected message type")
                return False
        else:
            await websocket.close(code=1002, reason="Invalid initial message")
            return False
    except json.JSONDecodeError:
        if websocket.open:
            await websocket.close(code=1007, reason="Invalid JSON")
        return False
    except websockets.exceptions.ConnectionClosed:
        if (peer_ip, requesting_username) in pending_approvals:
            del pending_approvals[(peer_ip, requesting_username)]
        return False
    except Exception as e:
        if websocket.open:
            await websocket.close(code=1011, reason="Internal server error")
        if (peer_ip, requesting_username) in pending_approvals:
            del pending_approvals[(peer_ip, requesting_username)]
        return False