"""Sig-Net Protocol Framework - UDP Multicast Transport.

Optional utilities for sending and receiving Sig-Net packets via UDP multicast.
Uses Python stdlib socket module for cross-platform compatibility.
"""

from __future__ import annotations

import socket
import struct

from .constants import MULTICAST_TTL, SIGNET_UDP_PORT
from .send import calculate_multicast_address


class MulticastSender:
    """Context manager for sending Sig-Net packets via UDP multicast."""

    def __init__(self, interface_ip: str = "", ttl: int = MULTICAST_TTL) -> None:
        self._interface_ip = interface_ip
        self._ttl = ttl
        self._sock: socket.socket | None = None

    def __enter__(self) -> MulticastSender:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_TTL,
            struct.pack("b", self._ttl),
        )
        if self._interface_ip:
            self._sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(self._interface_ip),
            )
        # Enable loopback so sender can see own packets
        self._sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_LOOP,
            1,
        )
        return self

    def __exit__(self, *args: object) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def send(self, packet: bytes, universe: int) -> None:
        """Send a packet to the multicast group for the given universe."""
        if self._sock is None:
            raise RuntimeError("Sender not open — use as context manager")
        addr = calculate_multicast_address(universe)
        self._sock.sendto(packet, (addr, SIGNET_UDP_PORT))


class MulticastReceiver:
    """Context manager for receiving Sig-Net packets from a multicast group."""

    def __init__(
        self,
        universe: int,
        interface_ip: str = "",
        timeout: float = 3.0,
    ) -> None:
        self._universe = universe
        self._interface_ip = interface_ip
        self._timeout = timeout
        self._sock: socket.socket | None = None

    def __enter__(self) -> MulticastReceiver:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Some platforms also need SO_REUSEPORT
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass

        self._sock.bind(("", SIGNET_UDP_PORT))

        # Join multicast group
        mcast_addr = calculate_multicast_address(self._universe)
        if self._interface_ip:
            mreq = socket.inet_aton(mcast_addr) + socket.inet_aton(self._interface_ip)
        else:
            mreq = socket.inet_aton(mcast_addr) + struct.pack("!I", socket.INADDR_ANY)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        if self._timeout is not None:
            self._sock.settimeout(self._timeout)

        return self

    def __exit__(self, *args: object) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def receive(self, bufsize: int = 1500) -> tuple[bytes, tuple[str, int]]:
        """Receive a packet. Returns (data, (sender_addr, sender_port))."""
        if self._sock is None:
            raise RuntimeError("Receiver not open — use as context manager")
        data, addr = self._sock.recvfrom(bufsize)
        return data, addr
