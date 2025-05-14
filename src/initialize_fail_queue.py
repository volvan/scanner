import json
import sys

from rmq.rmq_manager import RMQManager
from utils.probe_handler import ProbeHandler
from database.db_manager import db_ports, DatabaseManager
from utils.worker_handler import DBWorker

from config.scan_config import FAIL_QUEUE, OUTPUT_FAIL_QUEUE
from config.logging_config import logger

# The queue we consume retries from
INPUT_FAIL_QUEUE = FAIL_QUEUE


def retry_callback(ch, method, properties, body):
    """Retry one IP:port, route still-unknown to OUTPUT_FAIL_QUEUE."""
    # 1) parse
    try:
        task = json.loads(body)
        ip = task["ip"]
        port = task["port"]
    except Exception as e:
        logger.warning(f"[RetryScan] Bad payload, dropping: {e} :: {body!r}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return

    # 2) scan
    try:
        handler = ProbeHandler(ip, str(port))
        scan = handler.scan()
        state = scan["state"]
        service = scan["service"]
        proto = scan["protocol"]
        product = scan["product"]
        version = scan["version"]
        cpe = scan["cpe"]
        os_info = scan["os"]
        duration = scan["duration"]

        record = {
            "ip": ip,
            "port": port,
            "port_state": state,
            "port_service": service,
            "port_protocol": proto,
            "port_product": product,
            "port_version": version,
            "port_cpe": cpe,
            "port_os": os_info,
            "duration": duration,
        }

        if state == "unknown":
            # still unknown → send to your new FINAL queue
            RMQManager(OUTPUT_FAIL_QUEUE).enqueue({"ip": ip, "port": port})
        elif state == "closed":
            # only enqueue known-closed if already in DB
            with DatabaseManager() as db:
                if db.port_exists(ip, port):
                    db_ports.put(record)
        else:
            # open or filtered → normal DB insert
            db_ports.put(record)

    except Exception as e:
        logger.error(f"[RetryScan] Crash retrying {ip}:{port}: {e}")
        # on any exception, push to your FINAL queue
        try:
            RMQManager(OUTPUT_FAIL_QUEUE).enqueue({"ip": ip, "port": port})
        except Exception as ex:
            logger.error(f"[RetryScan] Failed to enqueue to {OUTPUT_FAIL_QUEUE}: {ex}")

    finally:
        # ack the original message so it never blocks
        ch.basic_ack(delivery_tag=method.delivery_tag)


def main():
    """Consume INPUT_FAIL_QUEUE, retry tasks, and dispatch to OUTPUT_FAIL_QUEUE on second failure."""
    db_worker = DBWorker(enable_hosts=False, enable_ports=True)
    try:
        db_worker.start()

        rmq = RMQManager(INPUT_FAIL_QUEUE)
        rmq.channel.basic_qos(prefetch_count=1)
        rmq.channel.basic_consume(
            queue=INPUT_FAIL_QUEUE,
            on_message_callback=retry_callback
        )

        print(f"[*] Retrying from '{INPUT_FAIL_QUEUE}'. Secondary failures go to '{OUTPUT_FAIL_QUEUE}'.")
        rmq.channel.start_consuming()

    except KeyboardInterrupt:
        print("\n[RetryScan] Interrupted by user, shutting down…")
    except Exception as e:
        logger.critical(f"[RetryScan] Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        try:
            rmq.close()
        except Exception:
            pass
        db_worker.stop()


if __name__ == "__main__":
    main()