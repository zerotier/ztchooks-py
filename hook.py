#!/usr/bin/env python3

from datetime import datetime, timedelta
import hmac, hashlib
import unittest

class sig_header:
    def __init__(self):
        self.timestamp = None
        self.signatures = []

def verify_hook_signature(preSharedKey: bytes, sigHeader: str, payload: bytes, tolerance: timedelta) -> bool:
    try:
        sh = parse_header(sigHeader, tolerance)

        expectedSignature = generate_expected_signature(sh, preSharedKey, payload)

        for sig in sh.signatures:
            if hmac.compare_digest(expectedSignature, sig):
                return True

    except Exception as e:
        print(e)
        
    return False


def generate_expected_signature(sh: sig_header, preSharedKey: bytes, payload: bytes) -> bytearray:
    t = sh.timestamp.strftime('%s')
    msg = t + "," + payload.decode('utf-8')
    msgBytes = msg.encode()
    return hmac.digest(preSharedKey, msgBytes, hashlib.sha256)

def parse_header(header: str, tolerance: int) -> sig_header:
    sh = sig_header()

    pairs = header.split(",")

    sh = decode(sh, pairs, tolerance)

    if len(sh.signatures) == 0:
        raise RuntimeError("invalid signature")
    
    return sh

def decode(sh: sig_header, pairs: list[str], tolerance: timedelta) -> sig_header:
    for p in pairs:
        parts = p.split("=")
        if len(parts) != 2:
            raise RuntimeError("invalid header")

        item = parts[0]

        if item == "t":
            timestamp = datetime.fromtimestamp(int(parts[1]))
            sh.timestamp = timestamp
            
        elif item.startswith("v"):
            v = bytes.fromhex(parts[1])
            sh.signatures.append(v)

    now = datetime.now()
    expiration = sh.timestamp + tolerance
        
    if now > expiration:
        raise RuntimeError("signature expired")
    
    return sh

class TestVerifySignature(unittest.TestCase):
    psk: bytes = bytes.fromhex('778c6dab5feca625c7831644d18c4d0e4b3a337bff8a1e1c8f938f9cc20e6536')
    signature: str = 't=1694033429,v1=04d87956d1953f28ac04d441f139fc655109e9b5c64396fb55dbdf567c735f86'
    payload: bytes = str.encode('{"hook_id":"ae76d4c0-c94e-4025-a648-2c504eb90e3c","org_id":"1bb4dc96-f311-4c4a-ac93-551cbc0fa3da","hook_type":"NETWORK_JOIN","network_id":"19d9808567a17ccf","member_id":"a02505e545"}')

    def test_verify_signature(self):
        self.assertTrue(verify_hook_signature(self.psk, self.signature, self.payload, timedelta(weeks=65535)))

    def test_invalid_signature_fails(self):
        badSig = self.signature.replace("4", "0")
        self.assertFalse(verify_hook_signature(self.psk, badSig, self.payload, timedelta(weeks=65535)))

    def test_expired_signature_fails(self):
        self.assertFalse(verify_hook_signature(self.psk, self.signature, self.payload, timedelta(seconds=1)))


if __name__=='__main__':
	unittest.main()
