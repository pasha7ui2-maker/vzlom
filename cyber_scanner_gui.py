"""CyberLab — offline security utilities plus authorized network diagnostics."""
import hashlib
import http.client
import ipaddress
import math
import re
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from urllib.parse import urlsplit

BG = "#0b1220"
PANEL = "#172338"
TEXT = "#e5edf8"
MUTED = "#9fb0c7"
CYAN = "#67e8f9"
GREEN = "#86efac"
YELLOW = "#fcd34d"
RED = "#fca5a5"
PORTS = (22, 80, 443, 8080, 8443)
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}
SUSPICIOUS_WORDS = {
    "login", "verify", "wallet", "password", "secure",
    "update", "account", "payment", "recover", "confirm",
}
COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty",
    "qwerty123", "admin", "letmein", "welcome", "iloveyou",
    "abc123", "111111", "123123", "пароль", "qwertyuiop",
}


class CyberLabApp:
    def __init__(self, root):
        self.root = root
        root.title("CyberLab — учебная киберлаборатория")
        root.geometry("900x700")
        root.minsize(760, 580)
        root.configure(bg=BG)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT,
                        padding=(16, 9), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#164e63")],
                  foreground=[("selected", "white")])
        style.configure("TProgressbar", troughcolor="#26364e",
                        background="#06b6d4", bordercolor="#26364e",
                        lightcolor="#06b6d4", darkcolor="#06b6d4")

        header = tk.Frame(root, bg=BG)
        header.pack(fill="x", padx=24, pady=(18, 12))
        tk.Label(header, text="CYBERLAB", font=("Segoe UI", 25, "bold"),
                 fg=CYAN, bg=BG).pack(anchor="w")
        tk.Label(header, text="Твоя учебная лаборатория кибербезопасности",
                 font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w")
        tk.Label(header, text="URL • ПАРОЛИ • SHA-256 • СЕТЬ",
                 font=("Consolas", 9, "bold"), fg=GREEN, bg=BG).pack(anchor="w", pady=(7, 0))

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self._build_url_tab()
        self._build_password_tab()
        self._build_hash_tab()
        self._build_network_tab()

        footer = tk.Label(root,
            text="Учебный инструмент. Сетевые проверки — только с разрешения владельца.",
            font=("Segoe UI", 8), fg=MUTED, bg=BG)
        footer.pack(pady=(0, 9))

    def _panel(self, tab, title, subtitle):
        outer = tk.Frame(tab, bg=BG)
        outer.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(outer, text=title, font=("Segoe UI", 16, "bold"),
                 fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(outer, text=subtitle, font=("Segoe UI", 9),
                 fg=MUTED, bg=BG, wraplength=790, justify="left").pack(anchor="w", pady=(3, 14))
        return outer

    def _entry(self, parent, variable=None, show=None):
        field = tk.Entry(parent, textvariable=variable, show=show,
                         font=("Segoe UI", 11), bg="#f8fafc", fg="#0f172a",
                         insertbackground="#0f172a", relief="flat")
        field.pack(fill="x", ipady=8, pady=(5, 10))
        return field

    def _button(self, parent, label, command, color="#0e7490"):
        return tk.Button(parent, text=label, command=command, bg=color,
                         fg="white", activebackground="#155e75",
                         activeforeground="white", relief="flat",
                         font=("Segoe UI", 9, "bold"), padx=14, pady=8,
                         cursor="hand2")

    def _output(self, parent, height=12):
        widget = scrolledtext.ScrolledText(
            parent, height=height, bg="#07101d", fg=TEXT,
            insertbackground="white", font=("Consolas", 9),
            relief="flat", padx=12, pady=10, wrap="word")
        widget.pack(fill="both", expand=True, pady=(10, 0))
        return widget

    def _build_url_tab(self):
        tab = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(tab, text="🔎 URL-инспектор")
        area = self._panel(tab, "Проверка подозрительных ссылок",
            "Анализ выполняется локально: программа не открывает ссылку и не отправляет её сторонним сервисам.")
        tk.Label(area, text="Вставь URL:", fg=TEXT, bg=BG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.url_var = tk.StringVar()
        self._entry(area, self.url_var)
        controls = tk.Frame(area, bg=BG)
        controls.pack(fill="x")
        self._button(controls, "АНАЛИЗИРОВАТЬ URL", self.inspect_url).pack(side="left")
        self._button(controls, "ОЧИСТИТЬ", lambda: self.url_var.set(""), "#334155").pack(side="left", padx=8)
        self.url_output = self._output(area)
        self.url_output.insert("end", "Подсказка: вставь ссылку из письма или сообщения. Мы проверим подозрительные признаки, не переходя по ней.\n")

    def inspect_url(self):
        raw = self.url_var.get().strip()
        self.url_output.delete("1.0", "end")
        if not raw or any(ord(c) < 32 for c in raw):
            self.url_output.insert("end", "Введи корректный URL.\n")
            return
        candidate = raw if "://" in raw else "https://" + raw
        try:
            parsed = urlsplit(candidate)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            host, port, parsed = None, None, None
        if not parsed or not host or parsed.scheme.lower() not in {"http", "https"}:
            self.url_output.insert("end", "Не удалось разобрать адрес. Нужна ссылка вида https://example.com/path\n")
            return

        score = 0
        findings = []
        def flag(points, message):
            nonlocal score
            score += points
            findings.append((points, message))

        if parsed.username or parsed.password:
            flag(30, "В адресе есть логин или пароль перед именем сайта — распространённый приём маскировки домена.")
        if parsed.scheme.lower() != "https":
            flag(15, "Используется HTTP без шифрования.")
        try:
            ipaddress.ip_address(host)
            flag(15, "Вместо доменного имени используется IP-адрес.")
        except ValueError:
            pass
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
            if any(label.startswith("xn--") for label in ascii_host.split(".")):
                flag(20, "Домен содержит IDN/punycode. Проверь, не маскирует ли он похожее написание бренда.")
        except UnicodeError:
            ascii_host = host.lower()
            flag(15, "В имени домена есть необычные Unicode-символы.")
        if ascii_host in SHORTENERS:
            flag(20, "Это сервис сокращения ссылок: конечный адрес скрыт.")
        if len(ascii_host.split(".")) > 4:
            flag(10, "У домена необычно много поддоменов.")
        if len(raw) > 140:
            flag(10, "Ссылка очень длинная; длинные URL сложнее визуально проверять.")
        if port not in (None, 80, 443):
            flag(10, f"Используется нестандартный порт: {port}.")
        combined = (parsed.path + " " + parsed.query).lower()
        words = sorted(word for word in SUSPICIOUS_WORDS if word in combined)
        if words:
            flag(8, "В пути или параметрах есть слова, часто встречающиеся в приманках: " + ", ".join(words) + ".")
        if "%" in raw:
            flag(5, "Есть percent-encoded символы. Проверь скрытые или закодированные части адреса.")
        if parsed.fragment and len(parsed.fragment) > 50:
            flag(3, "Очень длинный фрагмент после #.")

        if score >= 40:
            verdict, color = "ВЫСОКИЙ РИСК", RED
        elif score >= 20:
            verdict, color = "ЕСТЬ ПОДОЗРИТЕЛЬНЫЕ ПРИЗНАКИ", YELLOW
        else:
            verdict, color = "МАЛО ЯВНЫХ ПРИЗНАКОВ", GREEN

        self.url_output.insert("end", f"РЕЗУЛЬТАТ: {verdict}\n")
        self.url_output.insert("end", f"Условный балл риска: {min(score, 100)}/100\n")
        self.url_output.insert("end", f"Домен: {host}\nСхема: {parsed.scheme.lower()}\n\n")
        if findings:
            self.url_output.insert("end", "НАЙДЕННЫЕ ПРИЗНАКИ:\n")
            for points, note in findings:
                self.url_output.insert("end", f"  +{points:02d}  {note}\n")
        else:
            self.url_output.insert("end", "Явных подозрительных признаков из проверяемого списка не найдено.\n")
        self.url_output.insert("end", "\nВажно: это эвристика, а не антивирус и не гарантия безопасности. Даже низкий балл не означает, что ссылке можно доверять.\n")
        self.url_output.tag_configure("verdict", foreground=color, font=("Consolas", 11, "bold"))
        self.url_output.tag_add("verdict", "1.0", "1.end")

    def _build_password_tab(self):
        tab = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(tab, text="🔐 Пароли")
        area = self._panel(tab, "Локальная проверка пароля",
            "Пароль анализируется только в памяти этой программы: он никуда не отправляется и не сохраняется.")
        tk.Label(area, text="Пароль для проверки:", fg=TEXT, bg=BG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.password_var = tk.StringVar()
        self.password_entry = self._entry(area, self.password_var, show="•")
        row = tk.Frame(area, bg=BG)
        row.pack(fill="x")
        self.show_password = tk.BooleanVar(value=False)
        tk.Checkbutton(row, text="Показать пароль", variable=self.show_password,
                       command=self.toggle_password, bg=BG, fg=TEXT,
                       selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT).pack(side="left")
        self._button(row, "ПРОВЕРИТЬ", self.check_password).pack(side="left", padx=12)
        self._button(row, "ОЧИСТИТЬ", self.clear_password, "#334155").pack(side="left")
        self.password_result = self._output(area, 10)
        self.password_result.insert("end", "Совет: используй длинные уникальные пароли или фразу из нескольких случайных слов. Не вводи сюда пароль от важного аккаунта — для обучения придумай тестовый.\n")

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_password.get() else "•")

    def clear_password(self):
        self.password_var.set("")
        self.password_result.delete("1.0", "end")

    def check_password(self):
        password = self.password_var.get()
        self.password_result.delete("1.0", "end")
        if not password:
            self.password_result.insert("end", "Сначала введи тестовый пароль.\n")
            return
        lower = password.lower()
        score = 0
        notes = []
        if len(password) >= 16:
            score += 3
            notes.append("Длина 16+ символов — хороший вклад.")
        elif len(password) >= 12:
            score += 2
            notes.append("Длина 12–15 символов — неплохо, но можно длиннее.")
        elif len(password) >= 8:
            score += 1
            notes.append("Длина 8–11 символов — лучше увеличить.")
        else:
            notes.append("Слишком короткий пароль: стремись хотя бы к 14–16 символам.")
        categories = [
            (any(c.islower() for c in password), "Есть строчные буквы"),
            (any(c.isupper() for c in password), "Есть заглавные буквы"),
            (any(c.isdigit() for c in password), "Есть цифры"),
            (any(not c.isalnum() for c in password), "Есть специальные символы"),
        ]
        for present, note in categories:
            if present:
                score += 1
                notes.append(note)
        if lower in COMMON_PASSWORDS:
            score = 0
            notes.append("Этот пароль есть в локальном списке очень распространённых паролей.")
        if len(password) >= 6 and len(set(password)) <= 2:
            score = max(0, score - 3)
            notes.append("Слишком много повторяющихся символов.")
        if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", lower):
            score = max(0, score - 2)
            notes.append("Обнаружена простая последовательность символов.")
        if len(password) >= 4 and len(set(password)) == len(password) and len(password) >= 14:
            score += 1
        rating = "СЛАБЫЙ" if score <= 2 else ("СРЕДНИЙ" if score <= 5 else "СИЛЬНЫЙ")
        color = RED if score <= 2 else (YELLOW if score <= 5 else GREEN)
        pool = 0
        if any(c.islower() for c in password): pool += 26
        if any(c.isupper() for c in password): pool += 26
        if any(c.isdigit() for c in password): pool += 10
        if any(not c.isalnum() for c in password): pool += 32
        estimate = len(password) * math.log2(pool) if pool else 0
        self.password_result.insert("end", f"ОЦЕНКА: {rating}\n")
        self.password_result.insert("end", f"Длина: {len(password)} символов\n")
        self.password_result.insert("end", f"Грубая теоретическая оценка: около {estimate:.0f} бит\n\n")
        self.password_result.insert("end", "ЧТО УЧТЕНО:\n")
        for note in notes:
            self.password_result.insert("end", f"  • {note}\n")
        self.password_result.insert("end", "\nОценка приблизительная: она не учитывает все словари, утечки и особенности атак. Для важных аккаунтов используй менеджер паролей и уникальную случайную комбинацию.\n")
        self.password_result.tag_configure("verdict", foreground=color, font=("Consolas", 11, "bold"))
        self.password_result.tag_add("verdict", "1.0", "1.end")

    def _build_hash_tab(self):
        tab = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(tab, text="🧬 SHA-256")
        area = self._panel(tab, "Проверка целостности файла",
            "SHA-256 создаёт цифровой отпечаток файла. Сравни его с доверенным контрольным хешем, чтобы заметить изменение содержимого.")
        self.file_path = tk.StringVar()
        tk.Label(area, text="Файл:", fg=TEXT, bg=BG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self._entry(area, self.file_path)
        controls = tk.Frame(area, bg=BG)
        controls.pack(fill="x")
        self._button(controls, "ВЫБРАТЬ ФАЙЛ", self.choose_file).pack(side="left")
        self._button(controls, "ВЫЧИСЛИТЬ SHA-256", self.hash_file).pack(side="left", padx=8)
        tk.Label(area, text="Доверенный SHA-256 для сравнения (необязательно):",
                 fg=TEXT, bg=BG, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(16, 0))
        self.expected_hash = tk.StringVar()
        self._entry(area, self.expected_hash)
        self.hash_output = self._output(area, 9)
        self.hash_value = ""
        self._button(controls, "СОХРАНИТЬ ОТЧЁТ", self.save_hash_report, "#334155").pack(side="right")

    def choose_file(self):
        path = filedialog.askopenfilename(title="Выбери файл")
        if path:
            self.file_path.set(path)

    def hash_file(self):
        path = self.file_path.get().strip()
        if not path:
            messagebox.showinfo("Файл не выбран", "Сначала выбери файл.")
            return
        try:
            digest = hashlib.sha256()
            size = 0
            with open(path, "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
            self.hash_value = digest.hexdigest()
            expected = self.expected_hash.get().strip().lower()
            self.hash_output.delete("1.0", "end")
            self.hash_output.insert("end", f"Файл: {path}\nРазмер: {size:,} байт\nАлгоритм: SHA-256\n\nХЕШ:\n{self.hash_value}\n")
            if expected:
                if re.fullmatch(r"[0-9a-f]{64}", expected):
                    same = expected == self.hash_value
                    self.hash_output.insert("end", "\nСРАВНЕНИЕ: " + ("СОВПАДАЕТ — отпечатки одинаковы." if same else "НЕ СОВПАДАЕТ — файл отличается от доверенного образца.") + "\n")
                else:
                    self.hash_output.insert("end", "\nОШИБКА: ожидаемый хеш должен содержать ровно 64 шестнадцатеричных символа.\n")
            else:
                self.hash_output.insert("end", "\nДобавь доверенный SHA-256 выше, чтобы сравнить файл с эталоном.\n")
        except OSError as exc:
            messagebox.showerror("Не удалось прочитать файл", str(exc))

    def save_hash_report(self):
        if not self.hash_value:
            messagebox.showinfo("Нет результата", "Сначала вычисли SHA-256.")
            return
        destination = filedialog.asksaveasfilename(
            title="Сохранить отчёт", defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt")],
            initialfile="cyberlab_hash_report.txt")
        if destination:
            try:
                with open(destination, "w", encoding="utf-8") as report:
                    report.write(self.hash_output.get("1.0", "end").strip() + "\n")
                messagebox.showinfo("Готово", "Отчёт сохранён.")
            except OSError as exc:
                messagebox.showerror("Ошибка сохранения", str(exc))

    def _build_network_tab(self):
        tab = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(tab, text="🌐 Сеть")
        area = self._panel(tab, "Ограниченная диагностика сети",
            "Проверяет DNS, пять заранее заданных TCP-портов и базовые HTTPS-заголовки. Никаких эксплойтов или подбора паролей.")
        tk.Label(area, text="Домен или IP:", fg=TEXT, bg=BG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.network_target = tk.StringVar(value="127.0.0.1")
        self._entry(area, self.network_target)
        self.network_consent = tk.BooleanVar(value=False)
        tk.Checkbutton(area, text="Я владелец этой системы или получил разрешение на проверку",
                       variable=self.network_consent, bg=BG, fg=TEXT,
                       selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT).pack(anchor="w")
        controls = tk.Frame(area, bg=BG)
        controls.pack(fill="x", pady=(10, 0))
        self.network_button = self._button(controls, "ЗАПУСТИТЬ ДИАГНОСТИКУ", self.start_network_scan)
        self.network_button.pack(side="left")
        self.network_output = self._output(area, 13)
        self.network_output.insert("end", "Проверяй только собственные системы или цели с явным разрешением.\n")

    def _network_log(self, message):
        self.root.after(0, lambda: self._append_network(message))

    def _append_network(self, message):
        self.network_output.insert("end", message)
        self.network_output.see("end")

    def start_network_scan(self):
        host = self.network_target.get().strip()
        if not self.network_consent.get():
            messagebox.showwarning("Нужно подтверждение",
                "Подтверди, что у тебя есть разрешение владельца системы.")
            return
        if (not host or any(c in host for c in "/\\?#@ \t\r\n")
                or host.startswith("-")):
            messagebox.showerror("Неверная цель", "Введи только домен или IP-адрес.")
            return
        self.network_button.config(state="disabled", text="ПРОВЕРКА...")
        self.network_output.delete("1.0", "end")
        threading.Thread(target=self._network_scan, args=(host,), daemon=True).start()

    def _network_scan(self, host):
        try:
            self._network_log(f"Цель: {host}\n\n[ DNS ]\n")
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM)})
            for address in addresses:
                self._network_log(f"  {address}\n")

            self._network_log("\n[ TCP — ограниченная проверка портов ]\n")
            for port in PORTS:
                try:
                    with socket.create_connection((host, port), timeout=1.2):
                        status = "OPEN"
                except OSError:
                    status = "CLOSED / FILTERED"
                self._network_log(f"  {port}/tcp  {status}\n")

            self._network_log("\n[ HTTPS / ЗАГОЛОВКИ ]\n")
            connection = None
            try:
                connection = http.client.HTTPSConnection(
                    host, timeout=4, context=ssl.create_default_context())
                connection.request("HEAD", "/", headers={"User-Agent": "CyberLab/2.0"})
                response = connection.getresponse()
                headers = {key.lower(): value for key, value in response.getheaders()}
                self._network_log(f"  HTTPS доступен; HTTP {response.status}\n")
                for key, label in SECURITY_HEADERS.items():
                    state = "OK" if key in headers else "MISSING"
                    value = f": {headers[key]}" if key in headers else ""
                    self._network_log(f"  [{state}] {label}{value}\n")
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                self._network_log(f"  HTTPS проверить не удалось: {exc}\n")
            finally:
                if connection:
                    connection.close()
            self._network_log("\nГотово. Отсутствие заголовка само по себе не доказывает уязвимость.\n")
        except (socket.gaierror, OSError) as exc:
            self._network_log(f"\nОшибка: {exc}\n")
        finally:
            self.root.after(0, lambda: self.network_button.config(
                state="normal", text="ЗАПУСТИТЬ ДИАГНОСТИКУ"))


if __name__ == "__main__":
    root = tk.Tk()
    CyberLabApp(root)
    root.mainloop()
