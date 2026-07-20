#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived, StreamEnded, ConnectionTerminated, StreamReset


def grpc_frame(payload: bytes) -> bytes:
    return b'\x00' + struct.pack('!I', len(payload)) + payload


def serve(port: int, mode: str, messages: list[bytes], split: bool = False, pause_after_first: float = 0.0):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    print(f'LISTEN {port}', flush=True)
    conn_sock, addr = srv.accept()
    conn_sock.settimeout(5.0)
    h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
    h2.initiate_connection()
    conn_sock.sendall(h2.data_to_send())
    streams = {}
    sent = False
    try:
        while True:
            data = conn_sock.recv(65535)
            if not data:
                break
            events = h2.receive_data(data)
            for ev in events:
                if isinstance(ev, RequestReceived):
                    streams[ev.stream_id] = b''
                    print('REQUEST', ev.stream_id, ev.headers, flush=True)
                elif isinstance(ev, DataReceived):
                    streams[ev.stream_id] = streams.get(ev.stream_id, b'') + ev.data
                    h2.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    print('DATA', ev.stream_id, ev.data.hex(), flush=True)
                elif isinstance(ev, StreamEnded):
                    sid = ev.stream_id
                    print('STREAM_ENDED', sid, flush=True)
                    h2.send_headers(sid, [(':status', '200'), ('content-type', 'application/grpc')], end_stream=False)
                    if mode == 'unary':
                        body = grpc_frame(messages[0])
                        if split and len(body) > 2:
                            h2.send_data(sid, body[:2], end_stream=False)
                            h2.send_data(sid, body[2:], end_stream=False)
                        else:
                            h2.send_data(sid, body, end_stream=False)
                    else:
                        # Send first message split across frames and then two messages packed in one DATA frame.
                        bodies = [grpc_frame(m) for m in messages]
                        if pause_after_first > 0:
                            # Cancellation test: flush only the first response and give the
                            # client enough time to send RST_STREAM(CANCEL). If the client
                            # does not cancel, send the remaining messages and trailers.
                            h2.send_data(sid, bodies[0], end_stream=False)
                            conn_sock.sendall(h2.data_to_send())
                            try:
                                conn_sock.settimeout(pause_after_first)
                                more = conn_sock.recv(65535)
                                if more:
                                    for e2 in h2.receive_data(more):
                                        if isinstance(e2, StreamReset):
                                            print('RST_STREAM', e2.stream_id, e2.error_code, flush=True)
                                            return
                            except socket.timeout:
                                pass
                            finally:
                                conn_sock.settimeout(5.0)
                            for b in bodies[1:]:
                                h2.send_data(sid, b, end_stream=False)
                        elif split and len(bodies[0]) > 3:
                            h2.send_data(sid, bodies[0][:3], end_stream=False)
                            h2.send_data(sid, bodies[0][3:], end_stream=False)
                            if len(bodies) > 1:
                                h2.send_data(sid, b''.join(bodies[1:]), end_stream=False)
                        else:
                            for b in bodies:
                                h2.send_data(sid, b, end_stream=False)
                    h2.send_headers(sid, [('grpc-status', '0'), ('grpc-message', '')], end_stream=True)
                    conn_sock.sendall(h2.data_to_send())
                    sent = True
                    if mode == 'unary':
                        return
                elif isinstance(ev, StreamReset):
                    print('RST_STREAM', ev.stream_id, ev.error_code, flush=True)
                    return
                elif isinstance(ev, ConnectionTerminated):
                    print('GOAWAY', ev.error_code, flush=True)
                    return
            out = h2.data_to_send()
            if out:
                conn_sock.sendall(out)
            if sent and mode != 'unary':
                # Give client a moment to read trailers or send RST_STREAM in cancellation tests.
                time.sleep(0.2)
                return
    finally:
        conn_sock.close()
        srv.close()


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--mode', choices=['unary', 'server-streaming'], default='server-streaming')
    ap.add_argument('--message', action='append', default=[])
    ap.add_argument('--split', action='store_true')
    ap.add_argument('--pause-after-first', type=float, default=0.0)
    ns = ap.parse_args()
    msgs = [bytes.fromhex(x) for x in ns.message] or [bytes.fromhex('0a026f6b')]
    serve(ns.port, ns.mode, msgs, ns.split, ns.pause_after_first)
