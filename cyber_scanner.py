#!/usr/bin/env python3
"""CyberScanner: safe, basic network and HTTP security checks for authorized targets."""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from urllib.error import URLError
from urllib.request import Request, urlopen

DEFAULT_PORTS = (22, 80, 443, 8080, 8443)
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS: помогает принудительно использовать HTTPS.",
    "content-security-policy": "CSP: ограничивает источники загружаемого контента.",
    "x-content-type-options": "Защищает от MIME-sniffing (обычно значение nosniff).",
    "x-frame-options": "Помогает ограничить встраивание страницы во фреймы.",
    "referrer-policy": "Управляет передачей Referer.",
}


def parse_ports(value: str) -> list[int]:
    try:
        ports = sorted({int(part.strip()) for part in value.split(",")})
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Порты должны быть числами через запятую.") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("Допустимый диапазон портов: 1–65535.")
    if len(ports) > 20:
        raise argparse.ArgumentTypeError("За один запуск можно проверить не более 20 портов.")
    return ports


def check_ports(host: str, ports: list[int], timeout: float) -> None:
    print("\n[ TCP ]")
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                print(f"  {port:>5}/tcp  OPEN")
        except (TimeoutError, socket.timeout):
            print(f"  {port:>5}/tcp  FILTERED или TIMEOUT")
        except ConnectionRefusedError:
            print(f"  {port:>5}/tcp  CLOSED")
        except OSError as exc:
            print(f"  {port:>5}/tcp  ERROR: {exc}")


def check_http(host: str, timeout: float) -> None:
    url = f"https://{host}/"
    print("\n[ HTTPS / SECURITY HEADERS ]")
    request = Request(url, method="GET", headers={"User-Agent": "CyberScanner/0.1 (educational)"})
    try:
        context = ssl.create_default_context()
        with urlopen(request, timeout=timeout, context=context) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            print(f"  HTTPS доступен; HTTP status: {response.status}")
            for header, explanation in SECURITY_HEADERS.items():
                if header in headers:
                    print(f"  [OK]      {header}: {headers[header]}")
                else:
                    print(f"  [MISSING] {header} — {explanation}")
    except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        print(f"  Не удалось проверить HTTPS: {exc}")
        print("  Это не доказывает наличие уязвимости: сервис может не поддерживать HTTPS.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Базовая диагностика сети и HTTP-заголовков (только с разрешения владельца)."
    )
    parser.add_argument("host", help="Домен или IP-адрес разрешённой цели")
    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=list(DEFAULT_PORTS),
        help="Порты через запятую (по умолчанию: 22,80,443,8080,8443; максимум 20)",
    )
    parser.add_argument("--timeout", type=float, default=1.5, help="Таймаут соединения в секундах")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Подтвердить, что у тебя есть разрешение проверять эту систему",
    )
    args = parser.parse_args()

    if not args.authorized:
        parser.error("Перед проверкой подтверди разрешение владельца: добавь --authorized")
    if not 0.2 <= args.timeout <= 10:
        parser.error("--timeout должен быть от 0.2 до 10 секунд")

    host = args.host.strip()
    if not host or any(char in host for char in "/\\?#@"):
        parser.error("Укажи только доменное имя или IP, без URL-пути и параметров")

    print(f"CyberScanner 0.1 — цель: {host}")
    print("Проверка выполняется в учебных целях. Только разрешённые системы.")

    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        print("\n[ DNS ]")
        for address in addresses:
            print(f"  {host} -> {address}")
    except socket.gaierror as exc:
        print(f"\n[ DNS ] Не удалось определить адрес: {exc}")
        return 1

    check_ports(host, args.ports, args.timeout)
    check_http(host, args.timeout)
    print("\nГотово. Отсутствующий заголовок — повод проверить конфигурацию, а не автоматическое доказательство взлома.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
