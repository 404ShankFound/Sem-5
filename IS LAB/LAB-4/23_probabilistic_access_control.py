"""Question 23: Probabilistic access control

Calculate access from user trust, object sensitivity and environmental risk, then grant or deny access.
"""


class ProbabilisticAccess:
    def __init__(self, threshold=0.6):
        self.threshold = threshold

    def evaluate(self, trust, sensitivity, risk):
        score = 0.5 * trust + 0.3 * (1 - sensitivity) + 0.2 * (1 - risk)
        return score >= self.threshold, score


def main():
    print("==============================")
    print("PROBABILISTIC ACCESS CONTROL")
    print("==============================")
    print()
    ac = ProbabilisticAccess()
    granted, score = ac.evaluate(0.9, 0.2, 0.1)
    denied, score2 = ac.evaluate(0.3, 0.9, 0.8)
    print("High-trust request:", granted, "score:", f"{score:.2f}")
    print("Low-trust request:", denied, "score:", f"{score2:.2f}")


if __name__ == "__main__":
    main()
