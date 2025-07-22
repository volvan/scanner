#!/usr/bin/env python3
"""
monitor_rabbitmq.py

Polls RabbitMQ’s Management HTTP API and displays:
  - total connections
  - total channels

Reads defaults from .env:
  RMQ_HOST, RMQ_USER, RMQ_PASS

Usage:
  pip install requests python-dotenv
  python monitor_rabbitmq.py [--host HOST] [--port PORT]
                            [--user USER] [--password PASS]
                            [--vhost VHOST] [--interval INT]
"""

import os
import sys
import time
import argparse
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

DEFAULT_TIMEOUT = 1.5

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def fetch_count(url, auth):
    resp = requests.get(url, auth=auth, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    return len(resp.json())

def main():
    # Load .env
    load_dotenv()

    # Env defaults (AMQP port is ignored; we always use HTTP API port 15672 by default)
    env_host = os.getenv("RMQ_HOST")
    env_user = os.getenv("RMQ_USER")
    env_pass = os.getenv("RMQ_PASS")

    p = argparse.ArgumentParser(
        description="Monitor RabbitMQ connections & channels via HTTP API"
    )
    p.add_argument("--host",     help="RabbitMQ host (defaults to RMQ_HOST or 127.0.0.1)")
    p.add_argument(
        "--port",
        type=int,
        help="RabbitMQ Management HTTP API port (defaults to 15672)"
    )
    p.add_argument("--user",     help="API username (defaults to RMQ_USER)")
    p.add_argument("--password", help="API password (defaults to RMQ_PASS)")
    p.add_argument("--vhost",    default="/",  help="Virtual host to monitor")
    p.add_argument("--interval", default=DEFAULT_TIMEOUT,    type=int, help="Refresh interval (s)")
    args = p.parse_args()

    host = args.host or env_host or "127.0.0.1"
    port = args.port or 15672
    user = args.user or env_user
    password = args.password or env_pass

    if not user or not password:
        print(
            "Error: specify --user/--password or set RMQ_USER/RMQ_PASS in your .env",
            file=sys.stderr,
        )
        sys.exit(1)

    base_url = f"http://{host}:{port}/api"
    auth = HTTPBasicAuth(user, password)
    url_conn    = f"{base_url}/connections"
    url_channel = f"{base_url}/channels"

    try:
        while True:
            try:
                total_conns    = fetch_count(url_conn, auth)
                total_channels = fetch_count(url_channel, auth)
            except Exception as e:
                clear_screen()
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {e}", file=sys.stderr)
            else:
                clear_screen()
                now = time.strftime('%Y-%m-%d %H:%M:%S')
                print(f"RabbitMQ Monitor @ {now}")
                print(f"  Host:        {host}")
                print(f"  HTTP Port:   {port}")
                print(f"  Vhost:       {args.vhost!r}")
                print(f"  Connections: {total_conns}")
                print(f"  Channels:    {total_channels}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nExiting.")

if __name__ == "__main__":
    main()