"""Question 22: Time based access control

Grant access only within an allowed start/end time and according to other configured conditions.
"""

from datetime import datetime, timedelta


class TimeBasedAccess:
    def __init__(self, start_hour, end_hour):
        self.start_hour = start_hour
        self.end_hour = end_hour

    def can_access(self, moment=None):
        moment = moment or datetime.now()
        hour = moment.hour
        if self.start_hour <= self.end_hour:
            return self.start_hour <= hour < self.end_hour
        return hour >= self.start_hour or hour < self.end_hour


def main():
    print("==============================")
    print("TIME BASED ACCESS CONTROL")
    print("==============================")
    print()
    now = datetime.now()
    allow = TimeBasedAccess((now.hour - 1) % 24, (now.hour + 1) % 24)
    deny = TimeBasedAccess((now.hour + 2) % 24, (now.hour + 3) % 24)
    print("Current Time:", now.strftime("%H:%M:%S"))
    print("Allowed Window Access:", allow.can_access(now))
    print("Denied Window Access:", deny.can_access(now))
    print("Allowed Window:", f"{allow.start_hour:02d}:00 to {allow.end_hour:02d}:00")
    print("Denied Window:", f"{deny.start_hour:02d}:00 to {deny.end_hour:02d}:00")


if __name__ == "__main__":
    main()
