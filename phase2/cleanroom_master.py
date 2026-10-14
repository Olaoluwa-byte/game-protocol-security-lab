#!/usr/bin/env python3
"""Clean-room implementation of the observed C09 UDP protocol."""

MAGIC = b"\xc0\x9e"


def build_packet(stage: int, opcode: int, body: bytes = b"") -> bytes:
    """Build a C09 packet with an 8-bit additive checksum."""
    if len(body) > 65535:
        raise ValueError("Body too large")

    header = (
        MAGIC
        + bytes([stage, opcode])
        + len(body).to_bytes(2, "little")
    )

    data = header + body
    return data + bytes([sum(data) & 0xFF])


def parse_packet(data: bytes):
    """Validate and decode an incoming C09 packet."""
    if len(data) < 7:
        raise ValueError("Packet too short")

    if data[:2] != MAGIC:
        raise ValueError("Invalid magic")

    stage = data[2]
    opcode = data[3]
    body_length = int.from_bytes(data[4:6], "little")

    if len(data) != 6 + body_length + 1:
        raise ValueError("Invalid packet length")

    expected_checksum = sum(data[:-1]) & 0xFF

    if data[-1] != expected_checksum:
        raise ValueError("Invalid checksum")

    return stage, opcode, data[6:-1]


if __name__ == "__main__":
    hello = bytes.fromhex("c09e012101000081")

    stage, opcode, body = parse_packet(hello)

    print("Parsed stage:", stage)
    print("Parsed opcode:", hex(opcode))
    print("Parsed body:", body.hex())

    rebuilt = build_packet(stage, opcode, body)

    print("Rebuilt packet:", rebuilt.hex())
    print("Exact match:", rebuilt == hello)


def run_server(game_server_ip, host="0.0.0.0", port=7777):
    import secrets
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    print(f"C09 clean-room master listening on {host}:{port}")

    sessions = {}
    lobbies = []
    credentials = {
        "player1": "labdemo-only",
        "player2": "labdemo-two",
    }

    while True:
        data, address = sock.recvfrom(65535)

        try:
            stage, opcode, body = parse_packet(data)
        except ValueError as exc:
            print(f"Rejected packet from {address}: {exc}")
            continue

        print(
            f"Received {address}: "
            f"stage={stage}, opcode=0x{opcode:02x}, "
            f"body={body.hex()}"
        )

        if opcode == 0x21:
            xor_key = secrets.token_bytes(4)
            sessions[address] = {"xor_key": xor_key, "token": None}

            response_body = (
                b"\x00\x10\x00\x00"
                + xor_key
            )

            response = build_packet(stage, 0xA1, response_body)
            sock.sendto(response, address)

            print(f"Sent HELLO_ACK: {response.hex()}")
            print(f"Generated XOR key: {xor_key.hex()}")

        elif opcode == 0x22:
            session = sessions.get(address)

            if session is None:
                print("AUTH rejected: no handshake")
                continue

            try:
                offset = 0

                username_length = int.from_bytes(body[offset:offset+2], "little")
                offset += 2

                username = body[offset:offset+username_length].decode("utf-8")
                offset += username_length

                password_length = int.from_bytes(body[offset:offset+2], "little")
                offset += 2

                encrypted_password = body[offset:offset+password_length]
                offset += password_length

                if offset != len(body):
                    raise ValueError("Unexpected AUTH body length")

                if len(encrypted_password) != password_length:
                    raise ValueError("Truncated password")

                key = session["xor_key"]

                password_bytes = bytes(
                    value ^ key[i % 4]
                    for i, value in enumerate(encrypted_password)
                )

                password = password_bytes.decode("utf-8")

            except (ValueError, UnicodeDecodeError) as exc:
                print(f"Malformed AUTH request: {exc}")
                continue

            if credentials.get(username) == password:
                token = secrets.token_bytes(8)
                session["token"] = token

                response_body = bytes([0]) + token
                print(f"AUTH success: {username}")
            else:
                response_body = bytes([3])
                print(f"AUTH failed: {username}")

            response = build_packet(stage, 0xA2, response_body)
            sock.sendto(response, address)

            print(f"Sent AUTH response: {response.hex()}")

        elif opcode == 0x23:
            session = sessions.get(address)

            if session is None or session.get("token") is None:
                print("CREATE rejected: unauthenticated client")
                continue

            try:
                if len(body) < 11:
                    raise ValueError("CREATE body too short")

                token = body[:8]

                if token != session["token"]:
                    raise ValueError("Invalid session token")

                name_length = int.from_bytes(body[8:10], "little")
                expected_length = 8 + 2 + name_length + 1

                if len(body) != expected_length:
                    raise ValueError("Invalid CREATE body length")

                name = body[10:10 + name_length].decode("utf-8")
                capacity = body[-1]

            except (ValueError, UnicodeDecodeError) as exc:
                print(f"CREATE rejected: {exc}")
                continue

            lobby_id = len(lobbies) + 1

            lobbies.append({
                "id": lobby_id,
                "name": name,
                "max_players": capacity,
                "current_players": 0,
            })

            response_body = lobby_id.to_bytes(2, "little")
            response = build_packet(stage, 0xA3, response_body)
            sock.sendto(response, address)

            print(
                f"CREATE success: id={lobby_id}, "
                f"name={name!r}, capacity={capacity}"
            )
            print(f"Sent CREATE response: {response.hex()}")

        elif opcode == 0x24:
            session = sessions.get(address)

            if session is None or session.get("token") is None:
                print("LIST rejected: unauthenticated client")
                continue

            if body != session["token"]:
                print("LIST rejected: invalid session token")
                continue

            response_body = bytearray([len(lobbies)])

            for lobby in lobbies:
                name_bytes = lobby["name"].encode("utf-8")

                response_body += lobby["id"].to_bytes(2, "little")
                response_body += bytes([
                    lobby["current_players"],
                    lobby["max_players"],
                    len(name_bytes),
                ])
                response_body += name_bytes

            response = build_packet(stage, 0xA4, bytes(response_body))
            sock.sendto(response, address)

            print(f"LIST success: {len(lobbies)} lobbies")
            print(f"Sent LIST response: {response.hex()}")
        elif opcode == 0x25:
            session = sessions.get(address)

            if session is None or session.get("token") is None:
                print("JOIN rejected: unauthenticated client")
                continue

            if len(body) != 10:
                print("JOIN rejected: invalid request length")
                continue

            token = body[:8]
            lobby_id = int.from_bytes(body[8:10], "little")

            if token != session["token"]:
                print("JOIN rejected: invalid session token")
                continue

            lobby = next(
                (item for item in lobbies if item["id"] == lobby_id),
                None
            )

            if lobby is None:
                response_body = bytes([4])
                print(f"JOIN refused: lobby {lobby_id} not found")

            elif lobby["current_players"] >= lobby["max_players"]:
                response_body = bytes([4])
                print(f"JOIN refused: lobby {lobby_id} is full")

            else:
                lobby["current_players"] += 1

                game_ip = socket.inet_aton(game_server_ip)
                game_port = (10000).to_bytes(2, "big")

                response_body = bytes([0]) + game_ip + game_port

                print(
                    f"JOIN success: lobby={lobby_id}, "
                    f"players={lobby['current_players']}/"
                    f"{lobby['max_players']}"
                )

            response = build_packet(stage, 0xA5, response_body)
            sock.sendto(response, address)

            print(f"Sent JOIN response: {response.hex()}")
        else:
            print(f"Handler not implemented for opcode 0x{opcode:02x}")


if __name__ == "__main__":
    import sys

    if "--serve" in sys.argv:
        args = [a for a in sys.argv[1:] if a != "--serve"]
        run_server(args[0] if args else "192.168.252.4")
