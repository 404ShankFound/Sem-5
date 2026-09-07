"""Question 17: Diffie hellman key management

Integrate Diffie-Hellman key exchange into a key-management system and verify the shared secret.
"""

import hashlib


def dh_exchange(p=23, g=5, a=6, b=15):
    A = pow(g, a, p)
    B = pow(g, b, p)
    s1 = pow(B, a, p)
    s2 = pow(A, b, p)
    return {"p": p, "g": g, "A": A, "B": B, "s1": s1, "s2": s2}


def derive_session_key(secret):
    return hashlib.sha256(str(secret).encode()).hexdigest()


class DHKeyManager:
    def __init__(self):
        self.records = {}
        self.logs = []

    def register(self, name, a, p=23, g=5):
        self.records[name] = {"private": a, "public": pow(g, a, p)}
        self.logs.append(f"register -> {name}")

    def establish(self, alice, bob, p=23, g=5):
        a = self.records[alice]["private"]
        b = self.records[bob]["private"]
        session = dh_exchange(p, g, a, b)
        if session["s1"] != session["s2"]:
            raise ValueError("Shared secret verification failed")
        key = derive_session_key(session["s1"])
        self.logs.append(f"establish -> {alice} <-> {bob}")
        return session, key


def main():
    print("==============================")
    print("DIFFIE-HELLMAN KEY MANAGEMENT")
    print("==============================")
    print()
    manager = DHKeyManager()
    manager.register("Alice", 6)
    manager.register("Bob", 15)
    session, key = manager.establish("Alice", "Bob")
    print("Public Parameters:", {"p": session["p"], "g": session["g"]})
    print("Alice Public:", session["A"])
    print("Bob Public:", session["B"])
    print("Shared Secret Alice:", session["s1"])
    print("Shared Secret Bob:", session["s2"])
    print("Verified:", session["s1"] == session["s2"])
    print("Derived Session Key:", key)
    print()
    print("Audit Log:")
    for log in manager.logs:
        print(log)


if __name__ == "__main__":
    main()
