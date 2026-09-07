"""Question 19: Abac access control

Implement attribute-based access control using user, object and environment attributes with a policy function.
"""


def policy(user, obj, env):
    score = 0.5 * user["trust"] + 0.3 * (1 - obj["sensitivity"]) + 0.2 * (1 - env["risk"])
    return score >= 0.6, score


def main():
    print("==============================")
    print("ABAC ACCESS CONTROL")
    print("==============================")
    print()
    user1 = {"name": "Alice", "trust": 0.9, "department": "finance"}
    obj1 = {"name": "budget", "sensitivity": 0.2, "department": "finance"}
    env1 = {"risk": 0.1, "location": "office"}
    allowed, score = policy(user1, obj1, env1)
    print("Alice to budget:", allowed, "score:", f"{score:.2f}")

    user2 = {"name": "Eve", "trust": 0.3, "department": "guest"}
    obj2 = {"name": "budget", "sensitivity": 0.9, "department": "finance"}
    env2 = {"risk": 0.8, "location": "remote"}
    allowed2, score2 = policy(user2, obj2, env2)
    print("Eve to budget:", allowed2, "score:", f"{score2:.2f}")


if __name__ == "__main__":
    main()
