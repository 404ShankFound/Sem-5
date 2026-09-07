"""Question 9: Rabin key validation

Accept Rabin p,q from the user and validate that both are prime and congruent to 3 mod 4.
"""


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


def ask_int(prompt, default):
    try:
        raw = input(f"{prompt} [{default}]: ").strip()
    except EOFError:
        raw = ""
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print("Invalid integer. Using default.")
        return default


def main():
    print("==============================")
    print("RABIN KEY VALIDATION")
    print("==============================")
    print()
    p = ask_int("Enter p", 499)
    q = ask_int("Enter q", 547)
    p_ok = is_prime(p)
    q_ok = is_prime(q)
    p_mod = p % 4 == 3
    q_mod = q % 4 == 3
    print("p:", p)
    print("q:", q)
    print("p is prime:", p_ok)
    print("q is prime:", q_ok)
    print("p % 4 == 3:", p_mod)
    print("q % 4 == 3:", q_mod)
    print("Valid Rabin Key:", p_ok and q_ok and p_mod and q_mod and p != q)


if __name__ == "__main__":
    main()
