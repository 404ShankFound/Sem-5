#!/usr/bin/env python3
"""Minimal receive-only serial monitor for testing LPC1768 telemetry."""
import argparse
from datetime import datetime
import sys
import time

try:
    import serial
except ImportError:
    print("Missing PySerial. Run: python -m pip install -r requirements.txt")
    raise SystemExit(1)

def main():
    parser = argparse.ArgumentParser(description="Read-only LPC1768 UART monitor")
    parser.add_argument("--port", default="COM6", help="Serial port (default: COM6)")
    parser.add_argument("--baud", type=int, default=9600, help="Baud rate (default: 9600)")
    args = parser.parse_args()
    try:
        with serial.Serial(args.port, args.baud, timeout=1) as ser:
            print(f"Listening on {args.port} at {args.baud} baud. Ctrl+C to stop.")
            print("This tool only reads; it never transmits commands.")
            while True:
                line = ser.readline()
                if line:
                    print(f"[PC {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                          + line.decode("utf-8", errors="replace").rstrip())
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as exc:
        print(f"Serial error: {exc}", file=sys.stderr)
        raise SystemExit(2)

if __name__ == "__main__":
    main()
