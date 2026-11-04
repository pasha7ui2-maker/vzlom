"""CyberScanner GUI — educational checks for systems you own or are authorized to test."""
import socket
import ssl
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from urllib.request import Request, urlopen
from urllib.error import URLError

PORTS = (22, 80, 443, 8080, 8443)
HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

class CyberScannerApp:
    def __init__(self, root):
        self.root = root
        root.title("CyberScanner — учебный аудит")
        root.geometry("720x560")
        root.minsize(600, 460)
        root.configure(bg="#101827")

        tk.Label(root, text="CYBERSCANNER", font=("Segoe UI", 22, "bold"),
                 fg="#67e8f9", bg="#101827").pack(pady=(18, 2))
        tk.Label(root, text="Базовая диагностика сети и HTTPS",
                 font=("Segoe UI", 10), fg="#cbd5e1", bg="#101827").pack(pady=(0, 16))

        panel = tk.Frame(root, bg="#1e293b", padx=18, pady=16)
        panel.pack(fill="x", padx=20)
        tk.Label(panel, text="Домен или IP-адрес:", bg="#1e293b",
                 fg="white", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.target = tk.Entry(panel, font=("Segoe UI", 12), relief="flat")
        self.target.insert(0, "127.0.0.1")
        self.target.pack(fill="x", pady=(6, 12), ipady=7)

        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(panel, text="У меня есть разрешение проверять эту систему",
                       variable=self.consent, bg="#1e293b", fg="#e2e8f0",
                       selectcolor="#334155", activebackground="#1e293b",
                       activeforeground="white").pack(anchor="w")
        self.button = tk.Button(panel, text="НАЧАТЬ ПРОВЕРКУ", command=self.start_scan,
                                bg="#0891b2", fg="white", activebackground="#0e7490",
                                activeforeground="white", relief="flat",
                                font=("Segoe UI", 10, "bold"), padx=16, pady=9)
        self.button.pack(anchor="w", pady=(12, 0))

        self.output = scrolledtext.ScrolledText(root, bg="#0b1220", fg="#dbeafe",
                                                insertbackground="white",
                                                font=("Consolas", 10), relief="flat",
                                                padx=12, pady=12, wrap="word")
        self.output.pack(fill="both", expand=True, padx=20, pady=16)
        self.write("Готово к работе.\nПроверяй только собственные системы или цели с явным разрешением.\n")

    def write(self, text):
        self.output.insert("end", text)
        self.output.see("end")

    def start_scan(self):
        host = self.target.get().strip()
        if not self.consent.get():
            messagebox.showwarning("Нужно подтверждение",
                                   "Подтверди, что у тебя есть разрешение владельца системы.")
            return
        if not host or any(c in host for c in "/\\?#@ "):
            messagebox.showerror("Неверная цель", "Введи только домен или IP без URL и пробелов.")
            return
        self.button.config(state="disabled", text="ПРОВЕРКА...")
        self.output.delete("1.0", "end")
        threading.Thread(target=self.scan, args=(host,), daemon=True).start()

    def log(self, text):
        self.root.after(0, self.write, text)

    def finish(self):
        self.root.after(0, lambda: self.button.config(state="normal", text="НАЧАТЬ ПРОВЕРКУ"))

    def scan(self, host):
        try:
            self.log(f"Цель: {host}\n\n[ DNS ]\n")
            addresses = sorted({x[4][0] for x in socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM)})
            for address in addresses:
                self.log(f"  {address}\n")

            self.log("\n[ TCP — ограниченная проверка портов ]\n")
            for port in PORTS:
                try:
                    with socket.create_connection((host, port), timeout=1.2):
                        status = "OPEN"
                except (ConnectionRefusedError, OSError):
                    status = "CLOSED / FILTERED"
                self.log(f"  {port}/tcp  {status}\n")

            self.log("\n[ HTTPS / ЗАГОЛОВКИ ]\n")
            req = Request(f"https://{host}/", headers={"User-Agent": "CyberScanner/1.0"})
            try:
                with urlopen(req, timeout=4, context=ssl.create_default_context()) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    self.log(f"  HTTPS доступен; HTTP {response.status}\n")
                    for key, label in HEADERS.items():
                        self.log(f"  [{'OK' if key in headers else 'MISSING'}] {label}"
                                 + (f": {headers[key]}" if key in headers else "") + "\n")
            except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
                self.log(f"  HTTPS проверить не удалось: {exc}\n")

            self.log("\nГотово. Отсутствие заголовка само по себе не доказывает уязвимость.\n")
        except (socket.gaierror, OSError) as exc:
            self.log(f"\nОшибка: {exc}\n")
        finally:
            self.finish()

if __name__ == "__main__":
    root = tk.Tk()
    CyberScannerApp(root)
    root.mainloop()
