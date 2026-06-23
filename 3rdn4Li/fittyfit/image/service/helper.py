from flask import flash
from pikepdf import Pdf
import base64
import random
import hashlib
import time
import hmac
import struct
import string
import os
import uuid

""" This file contains some helper functions
"""

def totp(key, interval=60, past=0):
    # Generate the currect TOTP
    now=time.time() - past * 60
    try:
        key = key.encode()
        counter = struct.pack('>Q', int(now / interval))
        mac = hmac.new(key, counter, hashlib.sha256).digest()
        password = base64.b32encode(mac).decode().replace("=", "")
    except Exception as e:
        print(e)
        password = None
    return password

def generate_key(user, seed=time.time(), length=12):
    # Generate the TOTP key
    seed = str(int(seed))
    random.seed(user + seed)
    chars = string.ascii_letters + string.digits
    print(seed)
    return seed, "".join([random.choice(chars) for _ in range(length)])


def nft_transfer(data_folder, nft_send, nft_recv, owner, infos=None):
    # Transfer NFT helper
    try:
        nft = Pdf.open(nft_send)
        meta = nft.open_metadata()

        if "pdf:creator" in meta:
            creator = meta["pdf:creator"]
            if "MrFlag" in creator:
                flash(f"Ups, we cannot move this NFT...", "red")
                return False
        else:
            creator = infos["creator"]
        
        if "pdf:description" in meta:
            description = meta["pdf:description"]
        else:
            description = infos["description"]
        
        if "pdf:score" in meta:
            score = meta["pdf:score"]
        else:
            score = infos["score"]
        
        if "pdf:level" in meta:
            level = meta["pdf:level"]
        else:
            level = infos["level"]
        
        if "pdf:part" in meta:
            part = meta["pdf:part"]
        else:
            part = infos["part"]

        if "Metadata" in nft.Root:
            del nft.Root.Metadata           
            
        with nft.open_metadata() as meta:
            meta["pdf:creator"] = creator
            meta["pdf:description"] = description
            meta["pdf:score"] = score
            meta["pdf:level"] = level
            meta["pdf:part"] = part
            meta["pdf:owner"] = owner
            
        os.remove(nft_send)
        nft.save(nft_recv)
    except Exception as e:
        print(e)        
        broken_nft = os.path.join(data_folder, "damaged", f"{uuid.uuid4()}.pdf")
        nft.save(broken_nft)
        flash(f"Ups, something went wrong...</span><button class='btn-flat toast-action' onclick=report('{broken_nft}')>Report</button><span>", "red")
        return False
    return True
