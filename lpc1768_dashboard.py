#!/usr/bin/env python3
"""Read-only LPC1768 telemetry dashboard. PC -> device commands are never sent."""
import csv
import os
import queue
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    serial = None
    list_ports = None

APP_TITLE = "LPC1768 Clock — Read-only Monitor"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alarm_history.csv")
CSV_FIELDS = ["pc_received_at", "device_timestamp", "event_type", "details", "status", "device_state"]

class SerialReader(threading.Thread):
    def __init__(self, port, baud, output_queue, stop_event):
        super().__init__(daemon=True)
        self.port_name = port
        self.baud = baud
        self.output_queue = output_queue
        self.stop_event = stop_event
        self.ser = None

    def run(self):
        try:
            self.ser = serial.Serial(self.port_name, self.baud, timeout=0.25,
                                     write_timeout=0.25)
            # Deliberately no ser.write() calls: PC side is receive-only.
            self.output_queue.put(("connected", self.port_name))
            buffer = bytearray()
            while not self.stop_event.is_set():
                try:
                    chunk = self.ser.read(128)
                except Exception as exc:
                    self.output_queue.put(("disconnected", str(exc)))
                    break
                if not chunk:
                    continue
                buffer.extend(chunk)
                if len(buffer) > 4096:
                    buffer.clear()
                    self.output_queue.put(("parse_error", "Input line exceeded 4096 bytes; discarded"))
                    continue
                while b"\n" in buffer:
                    raw, _, remainder = buffer.partition(b"\n")
                    buffer = bytearray(remainder)
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        self.output_queue.put(("line", line))
        except Exception as exc:
            self.output_queue.put(("connect_error", str(exc)))
        finally:
            if self.ser is not None:
                try:
                    self.ser.close()
                except Exception:
                    pass
            self.output_queue.put(("worker_stopped", self.port_name))

class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1180x760")
        self.root.minsize(960, 620)
        self.events = queue.Queue()
        self.stop_event = None
        self.reader = None
        self.connected = False
        self.last_rx_monotonic = None
        self.last_message = "Not reported"
        self.state = {
            "RTC time/date": "Unknown",
            "Alarm": "Unknown",
            "Alarm state": "Idle / not reported",
            "Stopwatch": "Unknown",
            "Countdown": "Unknown",
            "Diagnostics": "Not reported",
        }
        self.all_rows = []
        self._build_ui()
        self._refresh_ports()
        self._poll_queue()
        self._watch_stale()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        conn = ttk.LabelFrame(outer, text="Serial connection (receive-only)", padding=10)
        conn.pack(fill="x")
        ttk.Label(conn, text="COM port").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.port_var = tk.StringVar(value="COM6")
        self.port_combo = ttk.Combobox(conn, textvariable=self.port_var, width=12)
        self.port_combo.grid(row=0, column=1, padx=(0, 12))
        ttk.Button(conn, text="Refresh ports", command=self._refresh_ports).grid(row=0, column=2, padx=4)
        ttk.Label(conn, text="Baud").grid(row=0, column=3, padx=(12, 6))
        self.baud_var = tk.StringVar(value="9600")
        ttk.Combobox(conn, textvariable=self.baud_var, values=("9600", "19200", "38400", "57600", "115200"),
                     width=9, state="readonly").grid(row=0, column=4, padx=(0, 12))
        self.connect_btn = ttk.Button(conn, text="Connect", command=self.connect)
        self.connect_btn.grid(row=0, column=5, padx=4)
        self.disconnect_btn = ttk.Button(conn, text="Disconnect", command=self.disconnect, state="disabled")
        self.disconnect_btn.grid(row=0, column=6, padx=4)
        self.conn_status = tk.StringVar(value="Disconnected")
        ttk.Label(conn, textvariable=self.conn_status).grid(row=0, column=7, padx=(14, 0), sticky="w")
        conn.columnconfigure(7, weight=1)

        status_frame = ttk.LabelFrame(outer, text="Live firmware-reported status", padding=10)
        status_frame.pack(fill="x", pady=(10, 8))
        self.status_vars = {}
        items = list(self.state.items())
        for idx, (name, value) in enumerate(items):
            row, col = divmod(idx, 3)
            card = ttk.Frame(status_frame, padding=6, relief="groove")
            card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
            ttk.Label(card, text=name, font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
            var = tk.StringVar(value=value)
            self.status_vars[name] = var
            ttk.Label(card, textvariable=var, wraplength=300).pack(anchor="w", pady=(4, 0))
            status_frame.columnconfigure(col, weight=1)

        info = ttk.Frame(outer)
        info.pack(fill="x", pady=(0, 8))
        self.last_msg_var = tk.StringVar(value="Last message: Not reported")
        self.last_rx_var = tk.StringVar(value="Last PC reception: Not reported")
        ttk.Label(info, textvariable=self.last_msg_var).pack(side="left", fill="x", expand=True)
        ttk.Label(info, textvariable=self.last_rx_var).pack(side="right")

        logs = ttk.LabelFrame(outer, text="Event log", padding=8)
        logs.pack(fill="both", expand=True)
        filters = ttk.Frame(logs)
        filters.pack(fill="x", pady=(0, 6))
        ttk.Label(filters, text="Category").pack(side="left")
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(filters, textvariable=self.filter_var,
                                         values=("All", "TIME", "ALARM", "TIMER", "STOPWATCH", "DIAG", "SYSTEM", "ERROR"),
                                         state="readonly", width=14)
        self.filter_combo.pack(side="left", padx=(5, 12))
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_rows())
        ttk.Label(filters, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._render_rows())
        ttk.Entry(filters, textvariable=self.search_var, width=28).pack(side="left", padx=5)
        ttk.Button(filters, text="Export CSV…", command=self.export_csv).pack(side="right", padx=4)
        ttk.Button(filters, text="Clear display", command=self.clear_display).pack(side="right", padx=4)

        columns = ("pc_time", "device_time", "category", "description", "status")
        self.tree = ttk.Treeview(logs, columns=columns, show="headings", height=14)
        headings = {
            "pc_time": ("PC reception time", 155),
            "device_time": ("Device timestamp", 145),
            "category": ("Category", 100),
            "description": ("Event / details", 470),
            "status": ("Status", 130),
        }
        for col, (label, width) in headings.items():
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, minwidth=70, anchor="w")
        yscroll = ttk.Scrollbar(logs, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(logs, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.pack(side="top", fill="both", expand=True)
        xscroll.pack(fill="x")
        yscroll.place(relx=1.0, rely=0.12, relheight=0.77, anchor="ne")

        footer = ttk.Label(outer, text="Read-only by design: controls remain on the LPC1768 physical keypad.",
                           foreground="#245b35")
        footer.pack(anchor="w", pady=(8, 0))

    def _refresh_ports(self):
        if list_ports is None:
            self.port_combo["values"] = ("COM6",)
            return
        ports = sorted(p.device for p in list_ports.comports())
        self.port_combo["values"] = ports
        if self.port_var.get() not in ports and ports:
            # Do not silently connect or claim that a listed port is usable.
            self.port_var.set("COM6" if "COM6" in ports else ports[0])

    def connect(self):
        if serial is None:
            messagebox.showerror("Missing dependency", "Install dependencies first:\npython -m pip install -r requirements.txt")
            return
        if self.connected or (self.reader and self.reader.is_alive()):
            return
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Select a port", "Choose a COM port first.")
            return
        try:
            baud = int(self.baud_var.get())
        except ValueError:
            messagebox.showerror("Invalid baud rate", "Choose a numeric baud rate.")
            return
        self.stop_event = threading.Event()
        self.reader = SerialReader(port, baud, self.events, self.stop_event)
        self.conn_status.set(f"Connecting to {port}…")
        self.connect_btn.configure(state="disabled")
        self.reader.start()

    def disconnect(self):
        if self.stop_event:
            self.stop_event.set()
        self.connected = False
        self.conn_status.set("Disconnecting…")
        self.disconnect_btn.configure(state="disabled")

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "connected":
                    self.connected = True
                    self.last_rx_monotonic = time.monotonic()
                    self.conn_status.set(f"Connected: {payload} @ {self.baud_var.get()} baud — waiting for telemetry")
                    self.connect_btn.configure(state="disabled")
                    self.disconnect_btn.configure(state="normal")
                    self._add_event("SYSTEM", f"Serial connection opened on {payload}", "CONNECTED", "")
                elif kind == "connect_error":
                    self.connected = False
                    self.conn_status.set(f"Connection failed: {payload}")
                    self.connect_btn.configure(state="normal")
                    self.disconnect_btn.configure(state="disabled")
                    self._add_event("ERROR", f"Could not open serial port: {payload}", "ERROR", "")
                    messagebox.showerror("Serial connection failed", str(payload))
                elif kind == "disconnected":
                    self.connected = False
                    self.conn_status.set(f"Disconnected: {payload}")
                    self.connect_btn.configure(state="normal")
                    self.disconnect_btn.configure(state="disabled")
                    self._add_event("ERROR", f"Serial link lost: {payload}", "DISCONNECTED", "")
                elif kind == "worker_stopped":
                    if not self.connected:
                        self.connect_btn.configure(state="normal")
                        self.disconnect_btn.configure(state="disabled")
                elif kind == "parse_error":
                    self._add_event("ERROR", str(payload), "MALFORMED", "")
                elif kind == "line":
                    self.last_rx_monotonic = time.monotonic()
                    self.last_message = payload
                    self.last_msg_var.set(f"Last message: {payload}")
                    self.last_rx_var.set("Last PC reception: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    self._handle_line(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_line(self, line):
        fields = [x.strip() for x in line.split(",")]
        pc_time = datetime.now().isoformat(timespec="seconds")
        category = fields[0].upper() if fields else "UNKNOWN"
        device_time = ""
        status = "INFO"
        details = line
        device_state = ""

        if category == "TIME" and len(fields) == 3:
            date_part, time_part = fields[1], fields[2]
            device_time = f"{date_part} {time_part}"
            self.status_vars["RTC time/date"].set(device_time)
            details = f"RTC update: {device_time}"
            status = "LIVE"
        elif category == "ALARM" and len(fields) >= 2:
            event = fields[1].upper()
            if event == "CONFIGURED" and len(fields) >= 4:
                self.status_vars["Alarm"].set(f"{fields[2]} ({fields[3]})")
                self.status_vars["Alarm state"].set("Configured / waiting")
                details = f"Alarm configured for {fields[2]} — {fields[3]}"
                device_time = self._maybe_time(fields, 4)
                status = "CONFIGURED"
            elif event in ("TRIGGERED", "ACKNOWLEDGED", "WRONG_ANSWER") and len(fields) >= 3:
                device_time = fields[2]
                if event == "TRIGGERED":
                    self.status_vars["Alarm state"].set("Triggered — awaiting keypad challenge")
                    details = "Alarm triggered"
                    status = "TRIGGERED"
                elif event == "ACKNOWLEDGED":
                    self.status_vars["Alarm state"].set("Acknowledged via keypad challenge")
                    details = "Alarm acknowledged on device"
                    status = "ACKNOWLEDGED"
                else:
                    details = "Incorrect alarm challenge answer"
                    status = "WRONG ANSWER"
            else:
                details = line
        elif category == "TIMER" and len(fields) >= 2:
            event = fields[1].upper()
            if event == "STARTED":
                self.status_vars["Countdown"].set(f"Running — set {fields[2] if len(fields)>2 else 'Not reported'}")
                status = "STARTED"
                details = "Countdown started" + (f" ({fields[2]})" if len(fields)>2 else "")
            elif event == "COMPLETED":
                self.status_vars["Countdown"].set("Completed")
                device_time = fields[2] if len(fields) > 2 else ""
                status = "COMPLETED"
                details = "Countdown completed"
            else:
                details = line
        elif category == "STOPWATCH" and len(fields) >= 2:
            event = fields[1].upper()
            self.status_vars["Stopwatch"].set("Running" if event == "STARTED" else "Stopped")
            details = "Stopwatch " + event.lower()
            status = event
        elif category == "DIAG" and len(fields) >= 3:
            diag_name, diag_result = fields[1], fields[2]
            self.status_vars["Diagnostics"].set(f"{diag_name}: {diag_result}")
            details = f"Diagnostic {diag_name}: {diag_result}"
            status = diag_result
            device_state = f"{diag_name}={diag_result}"
        elif category == "SYSTEM":
            status = "INFO"
            details = line
        else:
            category = "ERROR" if len(fields) < 2 else category
            status = "UNRECOGNIZED"
            details = f"Unrecognized or malformed telemetry: {line}"

        self._add_event(category, details, status, device_time, device_state, pc_time)

    @staticmethod
    def _maybe_time(fields, index):
        return fields[index] if len(fields) > index else ""

    def _add_event(self, category, details, status, device_time="", device_state="", pc_time=None):
        pc_time = pc_time or datetime.now().isoformat(timespec="seconds")
        row = {
            "pc_received_at": pc_time,
            "device_timestamp": device_time,
            "event_type": category,
            "details": details,
            "status": status,
            "device_state": device_state,
        }
        self.all_rows.append(row)
        self._append_csv(row)
        self._render_rows()

    def _append_csv(self, row):
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            needs_header = not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                if needs_header:
                    writer.writeheader()
                writer.writerow(row)
        except OSError as exc:
            self.conn_status.set(f"Logging warning: {exc}")

    def _render_rows(self):
        if not hasattr(self, "tree"):
            return
        category_filter = self.filter_var.get() if hasattr(self, "filter_var") else "All"
        query = self.search_var.get().lower() if hasattr(self, "search_var") else ""
        self.tree.delete(*self.tree.get_children())
        for row in self.all_rows:
            if category_filter != "All" and row["event_type"].upper() != category_filter:
                continue
            haystack = " ".join(str(v) for v in row.values()).lower()
            if query and query not in haystack:
                continue
            self.tree.insert("", "end", values=(
                row["pc_received_at"], row["device_timestamp"], row["event_type"],
                row["details"], row["status"]
            ))

    def clear_display(self):
        if messagebox.askyesno("Clear display", "Clear only the on-screen table? Saved CSV history will remain unchanged."):
            self.all_rows.clear()
            self._render_rows()

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            title="Export displayed event log", defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
            initialfile="lpc1768_event_export.csv")
        if not path:
            return
        try:
            category_filter = self.filter_var.get()
            query = self.search_var.get().lower()
            rows = [r for r in self.all_rows
                    if (category_filter == "All" or r["event_type"].upper() == category_filter)
                    and (not query or query in " ".join(str(v) for v in r.values()).lower())]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            messagebox.showinfo("Export complete", f"Exported {len(rows)} rows.")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def _watch_stale(self):
        if self.connected:
            if self.last_rx_monotonic is None:
                self.conn_status.set("Connected — waiting for telemetry")
            else:
                age = time.monotonic() - self.last_rx_monotonic
                if age > 10:
                    self.conn_status.set(f"Connected, but telemetry stale ({int(age)}s without message)")
                elif age > 3:
                    self.conn_status.set(f"Connected — no recent telemetry ({int(age)}s)")
                else:
                    self.conn_status.set("Connected — telemetry active")
        self.root.after(1000, self._watch_stale)

    def close(self):
        if self.stop_event:
            self.stop_event.set()
        self.root.after(150, self.root.destroy)

def main():
    root = tk.Tk()
    Dashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()
