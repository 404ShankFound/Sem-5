"""L3q1 securecorp secure communication

SecureCorp needs a scalable communication system for Finance, HR and Supply Chain subsystems. Implement RSA encryption, Diffie-Hellman key exchange, key generation, distribution and revocation, with support for adding future subsystems.
"""

import hashlib
import math


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % m


def rsa_keygen(p=383, q=503, e=17):
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        e = 65537
    d = modinv(e, phi)
    return {"public": {"n": n, "e": e}, "private": {"n": n, "d": d}}


def rsa_encrypt(data, public_key):
    return [pow(b, public_key["e"], public_key["n"]) for b in data]


def rsa_decrypt(blocks, private_key):
    return bytes(pow(b, private_key["d"], private_key["n"]) for b in blocks)


def dh_exchange(p=23, g=5, a=6, b=15):
    A = pow(g, a, p)
    B = pow(g, b, p)
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)
    return {"p": p, "g": g, "A": A, "B": B, "s1": s1, "s2": s2}


class SecureCorpSystem:
    def __init__(self):
        self.departments = {}
        self.logs = []

    def add_department(self, name):
        self.departments[name] = {"keys": rsa_keygen(), "active": True}
        self.logs.append(f"add -> {name}")

    def revoke_department(self, name):
        self.departments[name]["active"] = False
        self.logs.append(f"revoke -> {name}")

    def send_message(self, sender, recipient, message):
        if not self.departments.get(sender, {}).get("active"):
            raise PermissionError(f"{sender} is not active")
        if not self.departments.get(recipient, {}).get("active"):
            raise PermissionError(f"{recipient} is not active")
        pub = self.departments[recipient]["keys"]["public"]
        priv = self.departments[recipient]["keys"]["private"]
        cipher = rsa_encrypt(message.encode(), pub)
        recovered = rsa_decrypt(cipher, priv).decode()
        self.logs.append(f"msg {sender}->{recipient}: {message}")
        return cipher, recovered

    def dh_session(self, left, right):
        session = dh_exchange()
        key = hashlib.sha256(str(session["s1"]).encode()).hexdigest()
        self.logs.append(f"dh {left}<->{right}: {session['s1']}")
        return session, key


def main():
    print("==============================")
    print("SECURECORP SECURE COMMUNICATION")
    print("==============================")
    print()
    system = SecureCorpSystem()
    for dept in ["Finance", "HR", "SupplyChain"]:
        system.add_department(dept)
    cipher, recovered = system.send_message("Finance", "HR", "SALARY")
    session, key = system.dh_session("Finance", "HR")
    print("Finance -> HR Ciphertext:", cipher)
    print("Recovered Message:", recovered)
    print("DH Shared Secret Verified:", session["s1"] == session["s2"])
    print("Derived Session Key:", key)
    print()
    system.revoke_department("SupplyChain")
    try:
        print(system.send_message("Finance", "SupplyChain", "STATUS"))
    except Exception as exc:
        print("Denied:", exc)
    print()
    print("Adding Future Subsystem: Legal")
    system.add_department("Legal")
    cipher2, recovered2 = system.send_message("Legal", "Finance", "DOCS")
    print("Legal -> Finance Ciphertext:", cipher2)
    print("Recovered Message:", recovered2)
    print()
    print("Audit Log:")
    for log in system.logs:
        print(log)


if __name__ == "__main__":
    main()
