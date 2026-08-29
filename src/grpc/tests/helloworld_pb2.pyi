from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class HelloRequest(_message.Message):
    __slots__ = ("name", "num")
    NAME_FIELD_NUMBER: _ClassVar[int]
    NUM_FIELD_NUMBER: _ClassVar[int]
    name: str
    num: int
    def __init__(self, name: _Optional[str] = ..., num: _Optional[int] = ...) -> None: ...

class HelloReply(_message.Message):
    __slots__ = ("message", "num")
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    NUM_FIELD_NUMBER: _ClassVar[int]
    message: str
    num: int
    def __init__(self, message: _Optional[str] = ..., num: _Optional[int] = ...) -> None: ...
