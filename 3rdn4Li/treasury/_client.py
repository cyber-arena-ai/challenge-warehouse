"""pwntools menu-protocol client for faust-treasury (port 6789).

The upstream's flag->key map is replaced by a key generated per plant and
carried in the handle.
"""
from __future__ import annotations

import random
import string

import pwn

pwn.context.update(log_level="error")

PORT = 6789

MENU = {
    "welcome": b"Welcome to treasury!\n"
               b"You got so much treasure that you can't\n"
               b"store it all in one vault, but also don't\n"
               b"to worry about keeping track of all the\n"
               b"different ones? Let us worry about\n"
               b"handling those while you focus on getting\n"
               b"more!\n\n"
               b"Choose an action:\n"
               b"-> add treasure location\n"
               b"-> view treasure locations\n"
               b"-> update treasure location\n"
               b"-> print logs\n"
               b"-> quit\n"
               b"  > ",
    "add_entry": b"Give it a name: ",
    "add_desc": b"Describe it: ",
    "add_end": b"Great! We'll keep this information save for you! :)\n\n",
    "menu": b"Choose an action:\n"
            b"-> add treasure location\n"
            b"-> view treasure locations\n"
            b"-> update treasure location\n"
            b"-> print logs\n"
            b"-> quit\n"
            b"  > ",
    "goodbye": b"Goodbye!:)\n",
    "print_entry": b"Logs are for admins only!\nPassword: ",
    "print_end": b"Nice try! :)\nBut seriously: Logs are for admins ONLY!!\n\n",
    "update_entry": b"Sorry, feature not yet implemented! \n"
                    b"Please wait for the next release.\n\n",
    "view_entry": b"Location name: ",
    "view_desc": b"\n-------------\nDescription: ",
}


def generate_random_string(size):
    return "".join(random.choice(string.ascii_letters) for _ in range(size))


def _connect(ip):
    try:
        return pwn.remote(ip, PORT)
    except pwn.pwnlib.exception.PwnlibException:
        raise ConnectionRefusedError("Cannot connect to target")


def _drain_welcome(r):
    for _ in range(9):  # ascii art
        r.recvline()
    return r.recvuntil("quit\n  > ")


def add_treasure(ip, key, value):
    """0 = ok, 1 = protocol mismatch, 2 = key in use, 3 = save failed."""
    r = _connect(ip)
    if _drain_welcome(r) != MENU["welcome"]:
        r.close(); return 1
    r.sendline("add")
    if r.recvuntil("name: ") != MENU["add_entry"]:
        r.close(); return 1
    r.sendline(key)
    if r.recvuntil("Describe it: ") != MENU["add_desc"]:
        r.close(); return 1
    r.sendline(value)
    first = r.recv(numb=1)
    if first == b"T":
        r.close(); return 2
    if first == b"W":
        r.close(); return 3
    if first + r.recvuntil("save for you! :)\n\n") != MENU["add_end"]:
        r.close(); return 1
    if r.recvuntil("quit\n  > ") != MENU["menu"]:
        r.close(); return 1
    r.sendline("quit")
    r.recvuntil("Goodbye!:)\n")
    r.close()
    return 0


def view_treasure(ip, key):
    """Returns the stored description bytes, or None."""
    r = _connect(ip)
    if _drain_welcome(r) != MENU["welcome"]:
        r.close(); return None
    r.sendline("view")
    if r.recvuntil("Location name: ") != MENU["view_entry"]:
        r.close(); return None
    r.sendline(key)
    first = r.recv(numb=1)
    if first == b"N":
        r.close(); return None
    if r.recvuntil(key) != key.encode():
        r.close(); return None
    if r.recvuntil("Description: ") != MENU["view_desc"]:
        r.close(); return None
    desc = r.recvuntil("\n", drop=True)
    if r.recvuntil("\n") != b"\n":
        r.close(); return None
    if r.recvuntil("quit\n  > ") != MENU["menu"]:
        r.close(); return None
    r.sendline("quit")
    r.recvuntil("Goodbye!:)\n")
    r.close()
    return desc


def update_location(ip):
    r = _connect(ip)
    if _drain_welcome(r) != MENU["welcome"]:
        r.close(); return False
    r.sendline("update")
    if r.recvuntil("for the next release.\n\n") != MENU["update_entry"]:
        r.close(); return False
    if r.recvuntil("quit\n  > ") != MENU["menu"]:
        r.close(); return False
    r.sendline("quit")
    r.recvuntil("Goodbye!:)\n")
    r.close()
    return True


def print_logs(ip):
    r = _connect(ip)
    if _drain_welcome(r) != MENU["welcome"]:
        r.close(); return False
    r.sendline("print")
    if r.recvuntil("Password: ") != MENU["print_entry"]:
        r.close(); return False
    r.sendline(generate_random_string(8))
    if r.recvuntil("ONLY!!\n\n") != MENU["print_end"]:
        r.close(); return False
    if r.recvuntil("quit\n  > ") != MENU["menu"]:
        r.close(); return False
    r.sendline("quit")
    r.recvuntil("Goodbye!:)\n")
    r.close()
    return True
