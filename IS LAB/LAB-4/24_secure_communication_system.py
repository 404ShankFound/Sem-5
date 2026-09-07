"""Question 24: Secure communication system

Build a scalable multi-department system using RSA communication, Diffie-Hellman exchange, key management, revocation and new-system support.
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


def is_prime(n):
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
    for a in [2, 3, 5, 7, 11]:
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


class SecureCommSystem:
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
        public_key = self.departments[recipient]["keys"]["public"]
        private_key = self.departments[recipient]["keys"]["private"]
        cipher = rsa_encrypt(message.encode(), public_key)
        recovered = rsa_decrypt(cipher, private_key).decode()
        self.logs.append(f"msg {sender}->{recipient}: {message}")
        return cipher, recovered

    def establish_session(self, left, right):
        session = dh_exchange()
        key = hashlib.sha256(str(session["s1"]).encode()).hexdigest()
        self.logs.append(f"dh {left}<->{right}: {session['s1']}")
        return session, key


def main():
    print("==============================")
    print("SECURE COMMUNICATION SYSTEM")
    print("==============================")
    print()
    system = SecureCommSystem()
    for dept in ["Finance", "HR", "SupplyChain"]:
        system.add_department(dept)
    cipher, recovered = system.send_message("Finance", "HR", "PAYROLL")
    session, key = system.establish_session("Finance", "HR")
    print("Finance -> HR Ciphertext:", cipher)
    print("Recovered Message:", recovered)
    print("DH Publics:", {"A": session["A"], "B": session["B"]})
    print("DH Shared Secret Verified:", session["s1"] == session["s2"])
    print("Derived Session Key:", key)
    print()
    print("Revoking SupplyChain...")
    system.revoke_department("SupplyChain")
    try:
        print(system.send_message("Finance", "SupplyChain", "STATUS"))
    except Exception as exc:
        print("Denied:", exc)
    print()
    print("Adding New Subsystem: Sales")
    system.add_department("Sales")
    cipher2, recovered2 = system.send_message("Sales", "Finance", "REPORT")
    print("Sales -> Finance Ciphertext:", cipher2)
    print("Recovered Message:", recovered2)
    print()
    print("Audit Log:")
    for log in system.logs:
        print(log)


if __name__ == "__main__":
    main()
