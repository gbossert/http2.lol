#!/usr/bin/env python3

from netzob.all import *

def vocabulary():
    return [CONNECTION_PREFACE, SETTINGS, WINDOW_UPDATE, HEADERS, PRIORITY, GOAWAY, PING, GOAWAY, RST_STREAM, PUSH_PROMISE]

CONNECTION_PREFACE = Symbol(name = "PREFACE")
CONNECTION_PREFACE.fields = [
    Field(ASCII("PRI * HTTP/")),
    Field(name="version", domain=ASCII("2.0")),
    Field(ASCII("\r\n\r\nSM\r\n\r\n"))
]

HEADERS = Symbol(name = "HEADERS")
HEADERS.fields = [
    Field(name="Length"),
    Field(name="Type", domain=Raw('\x01')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Pad Length", domain=Repeat(Raw(nbBytes=4), nbRepeat=(0, 1))),
    Field(name="Stream Dependency", domain=Raw(nbBytes=4)),
    Field(name="Weight", domain=Repeat(Raw(nbBytes=1), nbRepeat=(0, 1))),
    Field(name="Header Block Fragment", domain=Raw(nbBytes=(0, 500))),
    Field(name="Padding", domain=Raw(nbBytes=(0, 500)))    
]
HEADERS.fields[0].domain = Size(HEADERS.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))

PRIORITY = Symbol(name = "PRIORITY")
PRIORITY.fields = [
    Field(name="Length"),
    Field(name="Type", domain=Raw('\x02')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Stream Dependency", domain=Raw(nbBytes=4)),
    Field(name="Weight", domain=Raw(nbBytes=1))
]
PRIORITY.fields[0].domain = Size(PRIORITY.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))

SETTINGS = Symbol(name = "SETTINGS")
SETTINGS.fields = [
    Field(name="Length"),
    Field(name="Type", domain=Raw('\x04')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Payload", domain=Repeat(
        Agg([
            Raw(nbBytes=2),
            Raw(nbBytes=4)
            ]), nbRepeat=(0, 100)
            ))

    
]
SETTINGS.fields[0].domain = Size(SETTINGS.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))

PING = Symbol(name = "PING")
PING.fields = [
    Field(name="Length"),
    Field(name="Type", domain=Raw('\x06')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Opaque Data", domain=Raw(nbBytes=8)),
]
PING.fields[0].domain = Size(PING.fields[4:],dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))

GOAWAY = Symbol(name = "GOAWAY")
GOAWAY.fields = [
    Field(name="Length"),
    Field(name="Type", domain=Raw('\x07')),
    Field(name="Flags", domain=Raw('\x00')),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Last-Stream-ID", domain=Raw(nbBytes=4)),
    Field(name="Error Code", domain=Raw(nbBytes=4)),
    Field(name="Additional Debug Data", domain=Raw(nbBytes=(0, 200))),        
]
GOAWAY.fields[0].domain = Size(GOAWAY.fields[4:],dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))


WINDOW_UPDATE = Symbol(name = "WINDOW_UPDATE")
WINDOW_UPDATE.fields = [
    Field(name="Length"),
    Field(name="Type", domain=Raw('\x08')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Window Size Increment", domain=Raw(nbBytes=4))
]
WINDOW_UPDATE.fields[0].domain = Size(WINDOW_UPDATE.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))


RST_STREAM = Symbol(name = "RST_STREAM")
RST_STREAM.fields = [
    Field(name="Length", domain=Raw(nbBytes=3)),
    Field(name="Type", domain=Raw('\x03')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=4)),
    Field(name="Error Code", domain=Raw(nbBytes=4))
]
RST_STREAM.fields[0].domain = Size(RST_STREAM.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))


PUSH_PROMISE = Symbol(name = "PUSH_PROMISE")
PUSH_PROMISE.fields = [
    Field(name="Length", domain=Raw(nbBytes=3)),
    Field(name="Type", domain=Raw('\x05')),
    Field(name="Flags", domain=Raw(nbBytes=1)),
    Field(name="Stream Identifier", domain=Raw(nbBytes=3)),
    Field(name="Pad Length", domain=Repeat(Raw(nbBytes=4), nbRepeat=(0, 1))),
    Field(name="Promised Stream ID", domain=Raw(nbBytes=4)),
    Field(name="Header Block Fragment", domain=Raw(nbBytes=(0, 500))),
    Field(name="Padding", domain=Raw(nbBytes=(0, 500)))    
]
PUSH_PROMISE.fields[0].domain = Size(PUSH_PROMISE.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))


def __specialize(symbol, presets):
    path = MessageSpecializer(presets = presets).specializeSymbol(symbol)
    return TypeConverter.convert(path.generatedContent, BitArray, Raw)


def preface_valid():
    return preface(version = "2.0")

def preface_invalid():
    return preface(version = "3.0")

def preface(version):
    return __specialize(CONNECTION_PREFACE, {        
        "version": version
    })


def ping(ack = False, sid = "\x00\x00\x00\x00", opaque_data = "\x07\x06\x05\x04\x03\x02\x01\x00"):

    flags = "\x00"
    if ack:
        flags = "\x01"        
    
    return __specialize(PING, {
        "Length": TypeConverter.convert(len(opaque_data), Integer, Raw, src_unitSize = AbstractType.UNITSIZE_32)[-3:],
        "Flags": flags,
        "Stream Identifier": sid,
        "Opaque Data": opaque_data
    })

def various_ping():
    return {
        "PING": ping(),
        "PING_ACK": ping(ack = True),

        "PING_SID_FF": ping(sid = "\xff\xff\xff\xff"),
        "PING_SID_FF_ACK": ping(ack = True, sid = "\xff\xff\xff\xff"),
        
        "PING_SID_FF_SMALL_OPAQUE": ping(sid = "\xff\xff\xff\xff", opaque_data = "\x00"),
        "PING_SID_FF_ACK_LARGE_OPAQUE": ping(ack = True, sid = "\xff\xff\xff\xff", opaque_data = "\x07\x06\x05\x04\x03\x02\x01\x00\x07\x06\x05\x04\x03\x02\x01\x00")
    }

def headers(END_STREAM = False, END_HEADERS = False, sid = "\x00\x00\x00\x01", pad_length = b"", stream_dependency = b"", weight = b"", header_block_fragment = b"", padding = b""):

    flags = 0
    
    if END_STREAM:
        flags |= 1

    if END_HEADERS:
        flags |= 4

    flags = TypeConverter.convert(flags, Integer, Raw)
    
    return __specialize(HEADERS, {
        "Flags": flags,
        "Stream Identifier": sid,
        "Pad Length": pad_length,
        "Stream Dependency": stream_dependency,
        "Weight": weight,
        "Header Block Fragment": header_block_fragment,
        "Padding": padding     
    })


def various_headers():
    return {
        "HEADERS": headers(),
        "HEADERS_END_STREAM": headers(END_STREAM = True),
        "HEADERS_END_HEADERS": headers(END_HEADERS = True),
        "HEADERS_END_HEADERS_END_STREAM": headers(END_HEADERS = True, END_STREAM = True),

        "HEADERS_END_STREAM_RANDOM_BLOCK": headers(header_block_fragment = "\xFF\x98\x23\xFF\x98\x23\xFF\x98\x23\xFF\x98\x23\xFF\x98\x23\xFF\x98\x23\xFF\x98\x23"),
        
    }

    
def setting(ack = False, sid = "\x00\x00\x00\x00", SETTINGS_HEADER_TABLE_SIZE = None, SETTINGS_ENABLE_PUSH = None, SETTINGS_MAX_CONCURRENT_STREAMS = None, SETTINGS_INITIAL_WINDOW_SIZE = None, SETTINGS_MAX_FRAME_SIZE = None, SETTINGS_MAX_HEADER_LIST_SIZE = None, payload = None):

    if not ack:
        flags = "\x00"
    else:
        flags = "\x01"

    if payload is None:
        payload = b""
        if SETTINGS_HEADER_TABLE_SIZE is not None:
            payload += b"\x00\x01" + SETTINGS_HEADER_TABLE_SIZE
        if SETTINGS_ENABLE_PUSH is not None:
            payload += b"\x00\x02" + SETTINGS_ENABLE_PUSH
        if SETTINGS_MAX_CONCURRENT_STREAMS is not None:
            payload += b"\x00\x03" + SETTINGS_MAX_CONCURRENT_STREAMS
        if SETTINGS_INITIAL_WINDOW_SIZE is not None:
            payload += b"\x00\x04" + SETTINGS_INITIAL_WINDOW_SIZE
        if SETTINGS_MAX_FRAME_SIZE is not None:
            payload += b"\x00\x05" + SETTINGS_MAX_FRAME_SIZE
        if SETTINGS_MAX_HEADER_LIST_SIZE is not None:
            payload += b"\x00\x06" + SETTINGS_MAX_HEADER_LIST_SIZE
            
    return __specialize(SETTINGS, {
        "Flags": flags,
        "Stream Identifier": sid,
        "Payload": payload
    })

def priority(sid = "\x00\x00\x00\x01", sdid = "\x00\x00\x00\x00", weight = "\xff"):
    
    return __specialize(PRIORITY, {
        "Length": TypeConverter.convert(len(sdid) + len(weight), Integer, Raw, src_unitSize = AbstractType.UNITSIZE_32)[-3:],
        "Flags": "\x00",
        "Stream Identifier": sid,
        "Stream Dependency": sdid,
        "Weight": weight
    })

def rst_stream(error_code = "\x00\x00\x00\x00", sid = "\x00\x00\x00\x01"):

    return __specialize(RST_STREAM, {        
        "Length": TypeConverter.convert(len(error_code), Integer, Raw, src_unitSize = AbstractType.UNITSIZE_32)[-3:],
        "Flags": "\x00",
        "Stream Identifier": sid,
        "Error Code": error_code
    })

def push_promise(END_HEADERS = False, sid = "\x00\x00\x00\x01", promised_stream_id = "\x00\x00\x00\x02", pad_length = b"", header_block_fragment = b"", padding = b""):

    flags = "\x00"
    if END_HEADERS:
        flags = "\x04"
    
    return __specialize(PUSH_PROMISE, {
        "Flags": flags,
        "Stream Identifier": sid,
        "Pad Length": pad_length,
        "Promised Stream ID": promised_stream_id,
        "Header Block Fragment": header_block_fragment,
        "Padding": padding        
    })


# def headers(sid = "\x00\x00\x00\x01"):
#     HEADERS = Symbol(name = "Headers")
#     HEADERS.fields = [
#         Field(name="Length", domain=Raw(nbBytes=3)),
#         Field(name="Type", domain=Raw('\x01')),
#         Field(name="Flags", domain=Raw('\x04')),
#         Field(name="Stream Identifier", domain=Raw(sid)),
#         ]
#     HEADERS.fields[0].domain = Size(HEADERS.fields[4:],dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))
#     return HEADERS

# def data(sid = '\x00\x00\x00\x01'):
#     DATA = Symbol(name = "data")
#     DATA.fields = [
#         Field(name="Length", domain=Raw(nbBytes=3)),
#         Field(name="Type", domain=Raw('\x00')),
#         Field(name="Flags", domain=Raw('\x00')),
#         Field(name="Stream Identifier", domain=Raw(sid)),
#         Field(name="Data", domain=Raw(nbBytes=0))
#     ]
#     DATA.fields[0].domain = Size(DATA.fields[4:], dataType = Raw(nbBytes=3, unitSize=AbstractType.UNITSIZE_32))
#     return DATA
