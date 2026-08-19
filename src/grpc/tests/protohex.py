#!/usr/bin/env python3

import argparse
import pathlib
import struct
import sys
import tempfile

from grpc_tools import protoc
from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
from google.protobuf import message_factory
from google.protobuf import text_format


def compile_proto(proto_file: pathlib.Path, import_paths: list[pathlib.Path]):
    descriptor_file = tempfile.NamedTemporaryFile(
        suffix=".pb",
        delete=False,
    )
    descriptor_file.close()

    args = [
        "protoc",
        *[f"-I{p}" for p in import_paths],
        f"--descriptor_set_out={descriptor_file.name}",
        "--include_imports",
        str(proto_file),
    ]

    rc = protoc.main(args)
    if rc != 0:
        raise RuntimeError(f"protoc failed with exit code {rc}")

    descriptor_set = descriptor_pb2.FileDescriptorSet()

    with open(descriptor_file.name, "rb") as f:
        descriptor_set.ParseFromString(f.read())

    pathlib.Path(descriptor_file.name).unlink()

    return descriptor_set


def build_pool(descriptor_set):
    pool = descriptor_pool.DescriptorPool()

    pending = list(descriptor_set.file)

    while pending:
        next_pending = []

        for fd in pending:
            try:
                pool.Add(fd)
            except Exception:
                next_pending.append(fd)

        if len(next_pending) == len(pending):
            raise RuntimeError("Cannot resolve proto dependencies")

        pending = next_pending

    return pool


def find_message(pool, descriptor_set, message_name):
    # Fully qualified name supplied.
    if "." in message_name:
        try:
            return pool.FindMessageTypeByName(message_name)
        except KeyError:
            pass

    # Try packages declared by the input proto files.
    for fd in descriptor_set.file:
        if fd.package:
            full_name = f"{fd.package}.{message_name}"
        else:
            full_name = message_name

        try:
            return pool.FindMessageTypeByName(full_name)
        except KeyError:
            pass

    raise RuntimeError(f"Message type not found: {message_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Encode a protobuf text-format message to binary hex"
    )

    parser.add_argument(
        "proto",
        help="Path to .proto file",
    )

    parser.add_argument(
        "message_type",
        help="Message type, e.g. HelloRequest or helloworld.HelloRequest",
    )

    parser.add_argument(
        "message",
        help='Protobuf text format, e.g. \'{name:"Anton"}\'',
    )

    parser.add_argument(
        "-I",
        "--proto-path",
        action="append",
        default=[],
        help="Additional proto import path",
    )

    parser.add_argument(
        "--grpc",
        action="store_true",
        help="Add the 5-byte gRPC message envelope",
    )

    args = parser.parse_args()

    proto_file = pathlib.Path(args.proto).resolve()

    import_paths = [
        pathlib.Path(p).resolve()
        for p in args.proto_path
    ]

    # Directory containing the supplied .proto is always an import path.
    if proto_file.parent not in import_paths:
        import_paths.insert(0, proto_file.parent)

    descriptor_set = compile_proto(
        proto_file,
        import_paths,
    )

    pool = build_pool(descriptor_set)

    descriptor = find_message(
        pool,
        descriptor_set,
        args.message_type,
    )

    cls = message_factory.GetMessageClass(descriptor)
    message = cls()

    text_format.Parse(args.message, message)

    data = message.SerializeToString()

    if args.grpc:
        data = b"\x00" + struct.pack(">I", len(data)) + data

    print(data.hex())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
