"""Processo consumidor da fila; não executa o código-fonte enviado pelo usuário."""
import argparse
import os
import signal
import socket
import threading

from api.jobs import JobStore


def run_once(store, handler, worker_id):
    claimed = store.claim(worker_id)
    if claimed is None:
        return False
    identity, payload = claimed
    try:
        result = handler(**payload)
        store.complete(identity, worker_id, result.scan_id)
    except Exception as error:
        store.fail(identity, worker_id, error)
    return True


def run_worker(store, handler, stop_event, worker_id=None, poll_interval=0.35):
    identity = worker_id or f"{socket.gethostname()}:{os.getpid()}"
    store.initialize()
    heartbeat_stop = threading.Event()

    def heartbeat():
        while not heartbeat_stop.is_set():
            store.heartbeat(identity)
            heartbeat_stop.wait(3)

    beater = threading.Thread(target=heartbeat, daemon=True)
    beater.start()
    try:
        while not stop_event.is_set():
            if not run_once(store, handler, identity):
                stop_event.wait(poll_interval)
    finally:
        heartbeat_stop.set()
        beater.join(5)
        store.disconnect(identity)


def main():
    parser = argparse.ArgumentParser(description="Worker de análises SAST")
    parser.add_argument("--health-check", action="store_true")
    args = parser.parse_args()
    # Import tardio: a API e o worker compartilham contratos, mas rodam em processos próprios.
    from api.main import job_store, _execute_scan
    if args.health_check:
        return 0 if any(worker.startswith(socket.gethostname() + ":") for worker in job_store.status()["workers"]) else 1
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    run_worker(job_store, _execute_scan, stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
