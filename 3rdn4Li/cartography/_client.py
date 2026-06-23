"""Raw-socket protocol client for faust-cartography (nclib menu protocol on
port 6666)."""
from __future__ import annotations

import logging

import nclib

log = logging.getLogger(__name__)

PORT = 6666


class ClientError(Exception):
    """Protocol-level failure (bad length / invalid range)."""


def connect(ip):
    try:
        conn = nclib.Netcat((ip, PORT), raise_timeout=True)
        conn.settimeout(2)
        return conn
    except nclib.NetcatError:
        return None


def new_sector(conn, size):
    conn.sendline(b"0")
    conn.recv_until(b"Enter the sector's size:\n")
    conn.sendline(str(size).encode("ASCII"))


def fill_sector(conn, pos, data):
    conn.sendline(b"1")
    conn.recv_until(b"Where do you want to write?\n")
    conn.sendline(str(pos).encode("UTF-8"))
    conn.recv_until(b"How much do you want to write?\n")
    conn.sendline(str(len(data)).encode("UTF-8"))
    conn.recv_until(b"Enter your sensor data:\n")
    conn.sendline(data.encode("UTF-8"))


def read_sector(conn, pos, length):
    conn.sendline(b"2")
    conn.recv_until(b"Where do you want to read?\n")
    conn.sendline(str(pos).encode("UTF-8"))
    conn.recv_until(b"How much do you want to read?\n")
    conn.sendline(str(length).encode("UTF-8"))
    data = conn.recv_until(b"\n")[:-1].decode("UTF-8")
    if len(data) != length:
        raise ClientError("unexpected length")
    if data == "Invalid range":
        raise ClientError("invalid range")
    return data


def save_sector(conn):
    conn.sendline(b"3")
    conn.recv_until(b"Saved sector as ")
    return conn.recv_until(b"\n").decode("UTF-8")[1:-2]


def load_sector(conn, name):
    conn.sendline(b"4")
    conn.recv_until(b"Enter sector name:\n")
    conn.sendline(name.encode("UTF-8"))
    return conn.recv_until(b"\n").decode("UTF-8") == "Sector loaded\n"
