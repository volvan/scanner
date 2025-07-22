#!/usr/bin/env python3
"""
monitor_postgres.py

– Total connections (active/idle/others)
– Connections by application_name
– This session’s LISTEN channels (via pg_listening_channels())

Reads defaults from .env:
  DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME

Usage:
  pip install psycopg2-binary python-dotenv
  python monitor_postgres.py [--host HOST] [--port PORT]
                             [--user USER] [--password PASS]
                             [--dbname NAME] [--interval INT]
"""

import os, sys, time, argparse
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

DEFAULT_TIMEOUT = 1.5

def clear_screen():
    os.system('cls' if os.name=='nt' else 'clear')

def fetch_conn_stats(conn):
    with conn.cursor() as cur:
        # total & breakdown
        cur.execute("""
            SELECT state,
                   count(*) 
              FROM pg_stat_activity 
             WHERE datname = %s 
             GROUP BY state
        """, (conn.info.dbname,))
        rows = cur.fetchall()
    stats = {'total': 0}
    for state, cnt in rows:
        stats[state] = cnt
        stats['total'] += cnt
    return stats

def fetch_by_app(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT application_name, count(*) 
              FROM pg_stat_activity 
             WHERE datname = %s 
               AND application_name <> '' 
             GROUP BY application_name
             ORDER BY 2 DESC
        """, (conn.info.dbname,))
        return cur.fetchall()

def fetch_my_listens(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT unnest(pg_listening_channels())")
        return [r[0] for r in cur.fetchall()]

def main():
    load_dotenv()
    env = lambda k: os.getenv(k) or ''
    parser = argparse.ArgumentParser()
    parser.add_argument("--host");    parser.add_argument("--port", type=int)
    parser.add_argument("--user");    parser.add_argument("--password")
    parser.add_argument("--dbname");  parser.add_argument("--interval", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    host = args.host or env("DB_HOST") or "127.0.0.1"
    port = args.port or int(env("DB_PORT") or 5432)
    user = args.user or env("DB_USER")
    pw   = args.password or env("DB_PASS")
    db   = args.dbname or env("DB_NAME")

    if not all([user,pw,db]):
        print("Error: set DB_USER/DB_PASS/DB_NAME in .env or via args", file=sys.stderr)
        sys.exit(1)

    conn_info = dict(host=host, port=port, user=user, password=pw, dbname=db)
    try:
        conn = psycopg2.connect(**conn_info)
        conn.autocommit = True
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        while True:
            clear_screen()
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"PostgreSQL Monitor @ {now}")
            print(f" DB: {db!r} @ {host}:{port}\n")

            # 1) connection states
            stats = fetch_conn_stats(conn)
            print(f" Total connections: {stats.get('total',0)}")
            for st in ('active','idle'):
                if st in stats:
                    print(f"   {st:>6}: {stats[st]}")
            for st,c in stats.items():
                if st not in ('total','active','idle') and st is not None:
                    # try:
                    print(f"   {st:>6}: {c}")
                    # finally: pass

            # 2) by application_name
            apps = fetch_by_app(conn)
            if apps:
                print("\n Connections by application_name:")
                for app, cnt in apps:
                    print(f"   {app or '<none>':<20} {cnt}")

            # 3) this session’s LISTEN channels
            try:
                listens = fetch_my_listens(conn)
                if listens:
                    print("\n This session’s LISTEN channels:")
                    for ch in listens:
                        print(f"   {ch}")
            except psycopg2.errors.UndefinedFunction:
                # pg_listening_channels not supported <9.1
                pass

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nBye.")
    finally:
        conn.close()

if __name__=="__main__":
    main()