"""Question 20: Mac dac access control

Implement Mandatory and/or Discretionary Access Control using classifications, clearances or an access-control matrix.
"""


class MAC:
    levels = {"unclassified": 0, "confidential": 1, "secret": 2, "topsecret": 3}

    def can_read(self, clearance, classification):
        return self.levels[clearance] >= self.levels[classification]

    def can_write(self, clearance, classification):
        return self.levels[clearance] <= self.levels[classification]


class DAC:
    def __init__(self):
        self.matrix = {}

    def grant(self, owner, user, resource, rights):
        self.matrix.setdefault(resource, {}).setdefault(user, set()).update(set(rights))

    def revoke(self, owner, user, resource, rights=None):
        if resource not in self.matrix or user not in self.matrix[resource]:
            return
        if rights is None:
            self.matrix[resource][user].clear()
        else:
            self.matrix[resource][user].difference_update(set(rights))

    def can_access(self, user, resource, right):
        return right in self.matrix.get(resource, {}).get(user, set())


def main():
    print("==============================")
    print("MAC / DAC ACCESS CONTROL")
    print("==============================")
    print()

    mac = MAC()
    print("MAC read (Secret -> Confidential):", mac.can_read("secret", "confidential"))
    print("MAC read (Confidential -> Secret):", mac.can_read("confidential", "secret"))
    print("MAC write (Secret -> Confidential):", mac.can_write("secret", "confidential"))
    print("MAC write (Confidential -> Secret):", mac.can_write("confidential", "secret"))
    print()

    dac = DAC()
    dac.grant("owner", "Alice", "file1", "rw")
    dac.grant("owner", "Bob", "file1", "r")
    print("DAC Alice read file1:", dac.can_access("Alice", "file1", "r"))
    print("DAC Bob write file1:", dac.can_access("Bob", "file1", "w"))
    dac.revoke("owner", "Bob", "file1", "r")
    print("DAC Bob read after revoke:", dac.can_access("Bob", "file1", "r"))


if __name__ == "__main__":
    main()
