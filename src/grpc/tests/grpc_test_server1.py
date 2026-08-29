#!/usr/bin/env python3

from concurrent import futures

import signal
import threading

import grpc
import helloworld_pb2
import helloworld_pb2_grpc


class Greeter(helloworld_pb2_grpc.GreeterServicer):

    # Unary <-> Unary
    def SayHello(self, request, context):
        print(f"SayHello: name={request.name}")
        return helloworld_pb2.HelloReply(
            message=f"1b36bee4-e5d4-4057-a9d5-a0a343aa36ca: {request.name} #{1}", num=1)

    # Unary <-> Stream
    def SayHelloStreamReply(self, request, context):
        print(f"SayHelloStreamReply name={request.name} num={request.num}")
        for i in range(request.num):
            yield helloworld_pb2.HelloReply(
                message=f"1b36bee4-e5d4-4057-a9d5-a0a343aa36ca: {request.name} #{i + 1}")

    #  Stream <-> Stream
    def SayHelloBidiStream(self, request_iterator, context):
        print(f"SayHelloBidiStream")
        for request in request_iterator:
            print(f"SayHelloBidiStream name={request.name} num={request.num}")
            yield helloworld_pb2.HelloReply(
                message=f"1b36bee4-e5d4-4057-a9d5-a0a343aa36ca: {request.name}")


def serve():
    stop_event = threading.Event()

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10)
    )
    helloworld_pb2_grpc.add_GreeterServicer_to_server(
        Greeter(),
        server)

    def handle_signal(signum, frame):
        print(
            f"\nSignal {signal.Signals(signum).name} received, shutting down...")
        stop_event.set()

    server.add_insecure_port("127.0.0.1:50051")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("gRPC test server listening on :50051")
    server.start()

    try:
        stop_event.wait()
    finally:
        server.stop(grace=5).wait()


if __name__ == "__main__":
    serve()
