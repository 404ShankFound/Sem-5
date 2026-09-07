import secrets
import hashlib
import hmac
from math import gcd

# ============================================================
# RSA
# ============================================================

def is_prime(n, rounds=8):
    if n < 2:
        return False

    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1))
        n |= 1

        if is_prime(n):
            return n


def rsa_keys(bits=512):

    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537

        if gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            return (e, n), (d, n)


def rsa_sign(message, private):

    d, n = private

    digest = hashlib.sha256(message).digest()
    h = int.from_bytes(digest, "big")

    return pow(h, d, n)


def rsa_verify(message, signature, public):

    e, n = public

    digest = hashlib.sha256(message).digest()
    h = int.from_bytes(digest, "big")

    return pow(signature, e, n) == h


# ============================================================
# DIFFIE-HELLMAN
# ============================================================

# Educational DH parameters
DH_P = 23
DH_G = 5


def dh_keys():

    private = secrets.randbelow(DH_P - 2) + 1
    public = pow(DH_G, private, DH_P)

    return private, public


# ============================================================
# SIMPLE ENCRYPTION
# ============================================================

def encrypt(data, key):

    nonce = secrets.token_bytes(16)

    stream = hashlib.sha256(
        key + nonce
    ).digest()

    # Repeat stream if required
    stream = (
        stream * ((len(data) // len(stream)) + 1)
    )[:len(data)]

    cipher = bytes(
        a ^ b for a, b in zip(data, stream)
    )

    mac = hmac.new(
        key,
        nonce + cipher,
        hashlib.sha256
    ).digest()

    return nonce, cipher, mac


def decrypt(nonce, cipher, mac, key):

    expected = hmac.new(
        key,
        nonce + cipher,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(mac, expected):
        raise ValueError("Integrity check failed")

    stream = hashlib.sha256(
        key + nonce
    ).digest()

    stream = (
        stream * ((len(cipher) // len(stream)) + 1)
    )[:len(cipher)]

    return bytes(
        a ^ b for a, b in zip(cipher, stream)
    )


# ============================================================
# KEY MANAGEMENT SYSTEM
# ============================================================

class KMS:

    def __init__(self):
        self.systems = {}

    def register(self, name):

        public, private = rsa_keys()

        self.systems[name] = {
            "public": public,
            "private": private,
            "active": True
        }

        print(
            f"[KMS] Registered subsystem: {name}"
        )

    def revoke(self, name):

        if name not in self.systems:
            raise ValueError("Unknown subsystem")

        self.systems[name]["active"] = False

        print(
            f"[KMS] Revoked keys for: {name}"
        )

    def active(self, name):

        return (
            name in self.systems
            and self.systems[name]["active"]
        )


# ============================================================
# SECURE COMMUNICATION
# ============================================================

class SecureCommunication:

    def __init__(self, kms):
        self.kms = kms

    def send(self, sender, receiver, message):

        if not self.kms.active(sender):
            raise PermissionError(
                f"{sender} is not active."
            )

        if not self.kms.active(receiver):
            raise PermissionError(
                f"{receiver} is not active."
            )

        # -------------------------------
        # Diffie-Hellman
        # -------------------------------

        sender_private, sender_public = dh_keys()
        receiver_private, receiver_public = dh_keys()

        shared1 = pow(
            receiver_public,
            sender_private,
            DH_P
        )

        shared2 = pow(
            sender_public,
            receiver_private,
            DH_P
        )

        if shared1 != shared2:
            raise ValueError(
                "Diffie-Hellman failed"
            )

        session_key = hashlib.sha256(
            str(shared1).encode()
        ).digest()

        # -------------------------------
        # Encrypt document
        # -------------------------------

        data = message.encode()

        nonce, cipher, mac = encrypt(
            data,
            session_key
        )

        # -------------------------------
        # RSA signature
        # -------------------------------

        signature = rsa_sign(
            data,
            self.kms.systems[sender]["private"]
        )

        return {
            "sender": sender,
            "receiver": receiver,
            "nonce": nonce,
            "cipher": cipher,
            "mac": mac,
            "signature": signature,
            "dh_public": sender_public,
            "dh_private": receiver_private
        }

    def receive(self, packet):

        sender = packet["sender"]
        receiver = packet["receiver"]

        if not self.kms.active(sender):
            raise PermissionError(
                f"{sender} is not active."
            )

        if not self.kms.active(receiver):
            raise PermissionError(
                f"{receiver} is not active."
            )

        # -------------------------------
        # Recreate DH shared secret
        # -------------------------------

        shared = pow(
            packet["dh_public"],
            packet["dh_private"],
            DH_P
        )

        session_key = hashlib.sha256(
            str(shared).encode()
        ).digest()

        # -------------------------------
        # Decrypt
        # -------------------------------

        data = decrypt(
            packet["nonce"],
            packet["cipher"],
            packet["mac"],
            session_key
        )

        # -------------------------------
        # Verify signature
        # -------------------------------

        public_key = self.kms.systems[
            sender
        ]["public"]

        if not rsa_verify(
            data,
            packet["signature"],
            public_key
        ):
            raise ValueError(
                "Signature verification failed"
            )

        print(
            f"[{receiver}] "
            "Signature verified successfully."
        )

        return data.decode()


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print("SECURECORP SECURE COMMUNICATION SYSTEM")
    print("=" * 65)

    kms = KMS()

    # -------------------------------
    # Register subsystems
    # -------------------------------

    kms.register("Finance System (A)")
    kms.register("HR System (B)")
    kms.register("Supply Chain System (C)")

    communication = SecureCommunication(kms)

    # -------------------------------
    # Finance -> HR
    # -------------------------------

    report = """
CONFIDENTIAL FINANCIAL REPORT

Revenue: $15,000,000
Operating Expenses: $9,000,000
Net Profit: $6,000,000

This document is confidential.
"""

    packet = communication.send(
        "Finance System (A)",
        "HR System (B)",
        report
    )

    print("\n[HR System (B)] Received:")
    print(
        communication.receive(packet)
    )

    # -------------------------------
    # Supply Chain -> Finance
    # -------------------------------

    order = """
PROCUREMENT ORDER

Supplier: Global Manufacturing Ltd.
Product: Industrial Components
Quantity: 500
Total Value: $250,000
"""

    packet = communication.send(
        "Supply Chain System (C)",
        "Finance System (A)",
        order
    )

    print("\n[Finance System (A)] Received:")
    print(
        communication.receive(packet)
    )

    # -------------------------------
    # Add new subsystem
    # -------------------------------

    print("\n" + "=" * 65)
    print("ADDING NEW SUBSYSTEM")
    print("=" * 65)

    kms.register("Legal System (D)")

    # -------------------------------
    # Revocation
    # -------------------------------

    print("\n" + "=" * 65)
    print("KEY REVOCATION TEST")
    print("=" * 65)

    kms.revoke("HR System (B)")

    try:

        communication.send(
            "Finance System (A)",
            "HR System (B)",
            "Confidential information"
        )

    except PermissionError as e:

        print(
            "[SECURITY] Communication blocked:",
            e
        )

    print("\nSystem execution completed.")


if __name__ == "__main__":
    main()