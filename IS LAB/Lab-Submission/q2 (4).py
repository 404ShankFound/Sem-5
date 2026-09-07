import os
import json
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta


# ============================================================
# RABIN CRYPTOSYSTEM
# ============================================================

class Rabin:

    @staticmethod
    def is_prime(n, rounds=10):
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

    @staticmethod
    def generate_prime(bits):
        while True:
            p = secrets.randbits(bits)
            p |= (1 << (bits - 1))
            p |= 1

            # Rabin requires p,q = 3 mod 4
            if p % 4 == 3 and Rabin.is_prime(p):
                return p

    @staticmethod
    def generate_keys(bits=1024):
        p = Rabin.generate_prime(bits // 2)
        q = Rabin.generate_prime(bits // 2)

        while p == q:
            q = Rabin.generate_prime(bits // 2)

        n = p * q

        # Public key = n
        # Private key = (p, q)
        return n, (p, q)

    @staticmethod
    def encrypt(message, n):
        m = int.from_bytes(message, "big")

        if m >= n:
            raise ValueError("Message is too large.")

        return pow(m, 2, n)

    @staticmethod
    def decrypt(ciphertext, private_key, n):
        """
        Rabin normally produces four possible plaintext roots.
        """

        p, q = private_key

        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)

        yp = pow(p, -1, q)
        yq = pow(q, -1, p)

        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        return [r1, r2, r3, r4]


# ============================================================
# CENTRALIZED KEY MANAGEMENT SERVICE
# ============================================================

class HealthcareKMS:

    def __init__(self, key_size=1024):
        self.key_size = key_size

        self.database = "healthcare_keys.json"
        self.audit_file = "healthcare_audit.log"
        self.master_file = "kms_master.key"

        self.facilities = {}

        # IMPORTANT:
        # Load the same master key every time the program starts.
        self.master_key = self.load_master_key()

        self.load_database()

    # ========================================================
    # MASTER KEY
    # ========================================================

    def load_master_key(self):

        if os.path.exists(self.master_file):
            with open(self.master_file, "rb") as f:
                return f.read()

        key = secrets.token_bytes(32)

        with open(self.master_file, "wb") as f:
            f.write(key)

        # Restrict file permissions on Linux
        try:
            os.chmod(self.master_file, 0o600)
        except OSError:
            pass

        return key

    # ========================================================
    # PRIVATE KEY PROTECTION
    # ========================================================

    def protect(self, private_key):
        """
        Educational authenticated encryption using
        HMAC-SHA256 generated keystream.
        """

        data = json.dumps(private_key).encode()
        nonce = secrets.token_bytes(16)

        stream = b""
        counter = 0

        while len(stream) < len(data):
            stream += hmac.new(
                self.master_key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256
            ).digest()
            counter += 1

        encrypted = bytes(
            a ^ b for a, b in zip(data, stream)
        )

        tag = hmac.new(
            self.master_key,
            nonce + encrypted,
            hashlib.sha256
        ).digest()

        return (nonce + tag + encrypted).hex()

    def unprotect(self, protected):
        raw = bytes.fromhex(protected)

        nonce = raw[:16]
        tag = raw[16:48]
        encrypted = raw[48:]

        expected = hmac.new(
            self.master_key,
            nonce + encrypted,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(tag, expected):
            raise ValueError("Private key integrity check failed.")

        stream = b""
        counter = 0

        while len(stream) < len(encrypted):
            stream += hmac.new(
                self.master_key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256
            ).digest()
            counter += 1

        data = bytes(
            a ^ b for a, b in zip(encrypted, stream)
        )

        return tuple(json.loads(data.decode()))

    # ========================================================
    # DATABASE
    # ========================================================

    def save_database(self):
        with open(self.database, "w") as f:
            json.dump(self.facilities, f, indent=4)

        try:
            os.chmod(self.database, 0o600)
        except OSError:
            pass

    def load_database(self):
        if not os.path.exists(self.database):
            return

        with open(self.database, "r") as f:
            self.facilities = json.load(f)

    # ========================================================
    # AUDIT LOG
    # ========================================================

    def log(self, operation, facility, details=""):
        entry = {
            "time": datetime.now().isoformat(),
            "operation": operation,
            "facility": facility,
            "details": details
        }

        with open(self.audit_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

        print(
            f"[AUDIT] {operation} | {facility} | {details}"
        )

    # ========================================================
    # KEY GENERATION / REGISTRATION
    # ========================================================

    def register(self, facility_id, facility_name):

        if facility_id in self.facilities:
            print(
                f"[KMS] {facility_name} already registered."
            )
            return

        public, private = Rabin.generate_keys(
            self.key_size
        )

        now = datetime.now()

        self.facilities[facility_id] = {
            "name": facility_name,
            "public_key": str(public),
            "private_key": self.protect(private),
            "created": now.isoformat(),
            "expires": (
                now + timedelta(days=365)
            ).isoformat(),
            "status": "ACTIVE",
            "version": 1
        }

        self.save_database()

        self.log(
            "KEY_GENERATION",
            facility_id,
            "Version 1"
        )

        print(
            f"[KMS] Registered: {facility_name}"
        )

    # ========================================================
    # PUBLIC KEY DISTRIBUTION
    # ========================================================

    def get_public_key(self, facility_id):

        facility = self.get_facility(facility_id)

        if facility["status"] != "ACTIVE":
            raise PermissionError("Key is revoked.")

        self.log(
            "PUBLIC_KEY_DISTRIBUTION",
            facility_id
        )

        return int(facility["public_key"])

    # ========================================================
    # PRIVATE KEY DISTRIBUTION
    # ========================================================

    def get_private_key(
        self,
        facility_id,
        token
    ):

        if token != "AUTHORIZED":
            self.log(
                "UNAUTHORIZED_ACCESS",
                facility_id
            )
            raise PermissionError(
                "Unauthorized private-key request."
            )

        facility = self.get_facility(facility_id)

        if facility["status"] != "ACTIVE":
            raise PermissionError("Key is revoked.")

        self.log(
            "PRIVATE_KEY_DISTRIBUTION",
            facility_id
        )

        return self.unprotect(
            facility["private_key"]
        )

    # ========================================================
    # REVOCATION
    # ========================================================

    def revoke(self, facility_id, reason):

        facility = self.get_facility(facility_id)

        facility["status"] = "REVOKED"

        self.save_database()

        self.log(
            "KEY_REVOCATION",
            facility_id,
            reason
        )

        print(
            f"[KMS] Key revoked: {facility['name']}"
        )

    # ========================================================
    # KEY RENEWAL
    # ========================================================

    def renew(self, facility_id):

        facility = self.get_facility(facility_id)

        public, private = Rabin.generate_keys(
            self.key_size
        )

        now = datetime.now()

        facility["public_key"] = str(public)
        facility["private_key"] = self.protect(private)
        facility["created"] = now.isoformat()
        facility["expires"] = (
            now + timedelta(days=365)
        ).isoformat()
        facility["status"] = "ACTIVE"
        facility["version"] += 1

        self.save_database()

        self.log(
            "KEY_RENEWAL",
            facility_id,
            f"Version {facility['version']}"
        )

        print(
            f"[KMS] Key renewed: {facility['name']}"
        )

    # ========================================================
    # AUTOMATIC 12-MONTH RENEWAL
    # ========================================================

    def automatic_renewal(self):

        now = datetime.now()

        for facility_id, facility in self.facilities.items():

            expiry = datetime.fromisoformat(
                facility["expires"]
            )

            if now >= expiry and facility["status"] == "ACTIVE":
                self.renew(facility_id)

    # ========================================================
    # HELPER
    # ========================================================

    def get_facility(self, facility_id):

        if facility_id not in self.facilities:
            raise ValueError("Facility not registered.")

        return self.facilities[facility_id]


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("=" * 60)
    print("HEALTHCARE INC. RABIN KEY MANAGEMENT SERVICE")
    print("=" * 60)

    kms = HealthcareKMS(key_size=1024)

    # --------------------------------------------------------
    # Register hospitals and clinic
    # --------------------------------------------------------

    kms.register("HOSP001", "Central Hospital")
    kms.register("HOSP002", "City Hospital")
    kms.register("CLINIC001", "Downtown Clinic")

    # --------------------------------------------------------
    # Public key distribution
    # --------------------------------------------------------

    print("\n--- PUBLIC KEY DISTRIBUTION ---")

    public_key = kms.get_public_key("HOSP001")

    print(
        "Central Hospital Public Key:",
        str(public_key)[:50] + "..."
    )

    # --------------------------------------------------------
    # Private key distribution
    # --------------------------------------------------------

    print("\n--- PRIVATE KEY DISTRIBUTION ---")

    private_key = kms.get_private_key(
        "HOSP001",
        "AUTHORIZED"
    )

    print("Private key provided to authorized user.")

    # --------------------------------------------------------
    # Unauthorized access
    # --------------------------------------------------------

    print("\n--- UNAUTHORIZED ACCESS TEST ---")

    try:
        kms.get_private_key(
            "HOSP001",
            "WRONG_TOKEN"
        )
    except PermissionError as e:
        print("[SECURITY]", e)

    # --------------------------------------------------------
    # Rabin encryption
    # --------------------------------------------------------

    print("\n--- RABIN ENCRYPTION ---")

    message = b"Patient-1001"

    ciphertext = Rabin.encrypt(
        message,
        public_key
    )

    print("Original:", message.decode())
    print("Encrypted:", str(ciphertext)[:60] + "...")

    roots = Rabin.decrypt(
        ciphertext,
        private_key,
        public_key
    )

    print(
        "Possible plaintext roots:",
        len(roots)
    )

    # --------------------------------------------------------
    # Key renewal
    # --------------------------------------------------------

    print("\n--- KEY RENEWAL ---")

    kms.renew("HOSP001")

    # --------------------------------------------------------
    # Key revocation
    # --------------------------------------------------------

    print("\n--- KEY REVOCATION ---")

    kms.revoke(
        "CLINIC001",
        "Facility closed"
    )

    try:
        kms.get_public_key("CLINIC001")
    except PermissionError as e:
        print("[SECURITY]", e)

    # --------------------------------------------------------
    # Automatic renewal
    # --------------------------------------------------------

    print("\n--- AUTOMATIC RENEWAL CHECK ---")

    kms.automatic_renewal()

    print("\nKMS operation completed.")


if __name__ == "__main__":
    main()