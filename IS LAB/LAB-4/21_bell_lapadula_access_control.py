"""Question 21: Bell lapadula access control

Implement Bell-LaPadula read/write rules using subject and object security levels.
"""


class BellLaPadula:
    levels = {"unclassified": 0, "confidential": 1, "secret": 2, "topsecret": 3}

    def can_read(self, subject_level, object_level):
        return self.levels[subject_level] >= self.levels[object_level]

    def can_write(self, subject_level, object_level):
        return self.levels[subject_level] <= self.levels[object_level]


def main():
    print("==============================")
    print("BELL-LA PADULA ACCESS CONTROL")
    print("==============================")
    print()
    blp = BellLaPadula()
    print("Secret subject reads Confidential object:", blp.can_read("secret", "confidential"))
    print("Confidential subject reads Secret object:", blp.can_read("confidential", "secret"))
    print("Secret subject writes Confidential object:", blp.can_write("secret", "confidential"))
    print("Confidential subject writes Secret object:", blp.can_write("confidential", "secret"))


if __name__ == "__main__":
    main()
