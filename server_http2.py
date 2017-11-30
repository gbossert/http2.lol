#!/usr/bin/env python3

import ssl
import time
import select
import socket
from threading import Thread
from threading import Lock
import struct
import inspect
import random
import os
import json
import hashlib
import redis

from hpack.hpack import Encoder, Decoder
from test_manager import TestManager
from fingerprint import KnowledgeBase

import sys
sys.path.insert(0, "netzob/src")

import http2
from netzob.all import *

CONNECTED_SOCKETS = []

class ClientHandler(Thread):

    def __init__(self, listen_port, client_socket, client_definition, test_manager, output_path, output_lock):
        super(ClientHandler, self).__init__()
        self.listen_port = listen_port
        self.client_socket = client_socket
        self.client_definition = client_definition
        self.test_manager = test_manager
        self.io_symbols = []
        self.output_path = output_path
        self.output_lock = output_lock

        self.redis_connection = redis.StrictRedis(host='localhost', port=6379, db=0)
        
        self.tests = {}
        for (func_name, func) in inspect.getmembers(self, predicate=inspect.ismethod):
            if func_name.startswith("test_"):
                self.tests[func_name] = func

    def run(self):
        print("Handling a new client...")

        try:
            test_plan = self.test_manager.get_test_plan(self.client_definition, self.listen_port)

            # search for remaining tests to execute
            remaining_test_names = set(self.tests.keys()) - set(test_plan.keys())

            if len(remaining_test_names) > 0:
                
                print("Found {} remaining tests".format(len(remaining_test_names)))
                test_name_to_execute = random.choice(list(remaining_test_names))
                test_plan[test_name_to_execute] = self.execute_test(self.tests[test_name_to_execute])

                progress_percent = int(((len(test_plan.keys()) + 1.0) / len(self.tests.keys())) * 100.0)
                self.store_progress_in_redis(progress_percent, self.client_definition[0], self.listen_port)

            if len(remaining_test_names) == 0:
                base = KnowledgeBase()
                classification = base.classify(test_plan)

                results = {
                    "classification": classification,
                    "test_plan": test_plan
                }

                print("Classification: {}".format(classification))
                if len(classification.keys()) > 0:
                    self.store_classification_in_redis(results, self.client_definition[0], self.listen_port)                
                    
                    # dump test plan
                    print("Dumping test plan")
                    result_path = os.path.join(self.output_path, "{}_{}.json".format(self.client_definition[0], self.listen_port))
                    self.output_lock.acquire()
                    try:
                        with open(result_path, "w") as fd:
                            json.dump(results, fd, indent=5)
                    finally:
                        self.output_lock.release()
                    print("Test plan dumped in {}".format(result_path))
                    
        except Exception as e:
            raise
        
        return

    def store_progress_in_redis(self, progress, client_ip, retained_port):
        results = self.redis_connection.get("ip_{}".format(client_ip))
        if results is None or len(results) == 0:
            print("ERROR: couldn't put the progress of a user since it cannot be found in db")
            return

        results = json.loads(results.decode("utf-8"))
        print("results={}".format(results))

        for result in results:
            print("result = '{}'".format(result))
            if result['retained_port'] == retained_port:
                result['progress'] = progress
                http2_id = result['http2_id']
                print("Storing progress in REDIS :): {}".format(progress))
                self.redis_connection.set("id_{}".format(http2_id), json.dumps(result))
                return

    def store_classification_in_redis(self, classification, client_ip, retained_port):


        results = self.redis_connection.get("ip_{}".format(client_ip))
        if results is None or len(results) == 0:
            print("ERROR: couldn't put the classification of a user since it cannot be found in db")
            return

        results = json.loads(results.decode("utf-8"))
        print("results={}".format(results))

        for result in results:
            print("result = '{}'".format(result))
            if result['retained_port'] == retained_port:
                result['classification'] = classification
                http2_id = result['http2_id']
                print("Storing classification in REDIS :)")
                self.redis_connection.set("id_{}".format(http2_id), json.dumps(result))
                return
        

    def __dump_fingerprint(self, test_plan):

        fingerprint = []

        for i_test, test_name in enumerate(test_plan.keys()):
            print("i={}, name:{}".format(i_test, test_name))

            test_result = test_plan[test_name]
            print("=====")
            print(test_result)
            main_values = ""
            for test_result in test_plan[test_name]:
                
                
                main_values += "".join([data[0] for data in test_result])

            h = hashlib.md5(main_values.encode("utf-8")).digest()
            print("h={}".format(h))
            v = struct.unpack('Q', h[:8])[0] + struct.unpack('Q', h[8:])[0]
            print("v={}".format(v))
            value = v % 100
            fingerprint.append("{}\t{}".format(i_test, value))

        
        fingerprint_path = os.path.join(self.output_path, "{}.dat".format(self.client_definition[0]))                    
        with open(fingerprint_path, 'w') as fd:
            fd.write('\n'.join(fingerprint))

    def execute_random_test(self):

        vocabulary = dict()
        vocabulary.update(http2.various_ping())
        vocabulary.update(http2.various_headers())


        print(vocabulary)
        # vocabulary.extend(http2.various_setting())

        # vocabulary.extend(http2.various_priority())
        # vocabulary.extend(http2.various_rst_stream())
        # vocabulary.extend(http2.various_push_promise())        

        to_send = [random.choice(list(vocabulary.keys())) for x in range(random.randint(4, 10))]
        test_name = ";".join(to_send)

        results = []
        self.init_target()
        self.send_data([http2.setting()])
        
        print("[ TEST CASE {} ]----------------------------------".format(test_name))
        data = self.__read_from_socket()
        recv_symbols = self.__parse_client_request(data)
        results.append(str(recv_symbols))
        
        
        for sym in to_send:
            try:
                print("SYM : {}: {}".format(sym, vocabulary[sym]))
                self.send_data([vocabulary[sym]])
                data = self.__read_from_socket()
                recv_symbols = self.__parse_client_request(data)
                results.append(str(recv_symbols))
            except Exception as e:
                results.append("ERROR")
        
        
        print(results)
        
        return test_name, results
        


    def execute_test(self, test_function):

        self.init_target()
        
        self.io_symbols = []
        try:
            test_function()            
        except Exception as e:
            print(e)
        finally:
            print("Closing the connection with {}".format(self.client_definition))
            self.client_socket.close()

        print(self.io_symbols)
        return self.io_symbols


    def test_case1(self):
        """
        http://httpwg.org/specs/rfc7540.html#ConnectionHeader:
        - The server connection preface consists of a potentially empty SETTINGS frame (Section 6.5) that MUST be the first frame the server sends in the HTTP/2 connection.


        This method triggers the following sequence
        - wait client preface
        - wait for everything the client has to say
        - send a "ping" request (not allowed by the specifications)
        """

        results = []

        print("[ TEST CASE 1 ]----------------------------------")
        data = self.__read_from_socket()
        recv_symbols = self.__parse_client_request(data)
        print("< {}".format(recv_symbols))

        print("> [PING]")
        self.send_data([http2.ping()])

        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        print("-------------------------------------------------")
        
    def test_case2(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        ACK (0x1): When set, bit 0 indicates that this frame acknowledges receipt and application of the peer's SETTINGS frame. When this bit is set, the payload of the SETTINGS frame MUST be empty. Receipt of a SETTINGS frame with the ACK flag set and a length field value other than 0 MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.
        """

        print("[ TEST CASE 2 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))        

        print("> [SETTINGS_ACK_PAYLOAD]")
        self.send_data([http2.setting(ack = True, SETTINGS_HEADER_TABLE_SIZE = b"\x00\x00\x11\x11")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        print("-------------------------------------------------")
        
    def test_case3(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        The stream identifier for a SETTINGS frame MUST be zero (0x0).

        """

        print("[ TEST CASE 3 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SID_01]")
        self.send_data([http2.setting(sid = "\x00\x00\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        print("-------------------------------------------------")

    def test_case4(self):
        """

        http://httpwg.org/specs/rfc7540.html#PING
        PING frames MUST contain 8 octets of opaque data in the payload.
        """

        print("[ TEST CASE 4 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PING]")
        self.send_data([http2.ping(opaque_data = "\x00\x01" * 4)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PING_SMALL_OPAQUE_DATA]")
        self.send_data([http2.ping(opaque_data = "\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PING_LARGE_OPAQUE_DATA]")
        self.send_data([http2.ping(opaque_data = "\x01\x01" * 16)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("-------------------------------------------------")
        

    def test_case5(self):
        """

        http://httpwg.org/specs/rfc7540.html#PING
        ACK(0x1) [...] An endpoint MUST NOT respond to PING frames containing this flag
        """

        print("[ TEST CASE 5 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PING_ACK]")
        self.send_data([http2.ping(ack = True, opaque_data = "\x00\x01" * 4)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case6(self):
        """

        http://httpwg.org/specs/rfc7540.html#PING
        PING frames are not associated with any individual stream. If a PING frame is received with a stream identifier field value other than 0x0, the recipient MUST respond with a connection error
        """

        print("[ TEST CASE 6 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PING_SID_01]")
        self.send_data([http2.ping(sid = "\x00\x00\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case7(self):
        """

        http://httpwg.org/specs/rfc7540.html#PRIORITY
        If a PRIORITY frame is received with a stream identifier of 0x0, the recipient MUST respond with a connection error
        """

        print("[ TEST CASE 7 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PRIORITY_SID_00]")
        self.send_data([http2.priority(sid = "\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case8(self):
        """

        http://httpwg.org/specs/rfc7540.html#PRIORITY
        Weight: An unsigned 8-bit integer representing a priority weight for the stream
        A PRIORITY frame with a length other than 5 octets MUST be treated as a stream error 
        """

        print("[ TEST CASE 8 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PRIORITY_WEIGHT_01020304]")
        self.send_data([http2.priority(weight = "\x01\x02\x03\x04")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case9(self):
        """

        http://httpwg.org/specs/rfc7540.html#PRIORITY
        The PRIORITY frame can be sent for a stream in the "idle" or "closed" state.
        """

        print("[ TEST CASE 9 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PRIORITY_SID_01020304]")
        self.send_data([http2.priority(sid = "\x01\x02\x03\x04")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case10(self):
        """

        http://httpwg.org/specs/rfc7540.html#RST_STREAM
        A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error
        """

        print("[ TEST CASE 10 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [RST_STREAM_LARGE_ERROR_CODE]")
        self.send_data([http2.rst_stream(error_code = "\x01\x02\x03\x04" * 4)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
    def test_case11(self):
        """

        http://httpwg.org/specs/rfc7540.html#RST_STREAM
        If a RST_STREAM frame is received with a stream identifier of 0x0, the recipient MUST treat this as a connection error 
        """

        print("[ TEST CASE 11 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [RST_STREAM_SID_00]")
        self.send_data([http2.rst_stream(sid = "\x00\x00\x00\x00", error_code = "\x01\x02\x03\x04")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case12(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        Implementations MUST support all of the parameters defined by this specification.

        """

        print("[ TEST CASE 12 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_HEADER_TABLE_SIZE_FF]")
        self.send_data([http2.setting(SETTINGS_HEADER_TABLE_SIZE = b"\x00\x00\x00\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_ENABLE_PUSH_0]")
        self.send_data([http2.setting(SETTINGS_ENABLE_PUSH = b"\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_MAX_CONCURRENT_STREAMS_FF]")
        self.send_data([http2.setting(SETTINGS_MAX_CONCURRENT_STREAMS = b"\x00\x00\xFF\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_MAX_CONCURRENT_STREAMS_FF]")
        self.send_data([http2.setting(SETTINGS_MAX_CONCURRENT_STREAMS = b"\x00\x00\xFF\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("> [SETTINGS_SETTINGS_INITIAL_WINDOW_SIZE_FF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("> [SETTINGS_SETTINGS_INITIAL_WINDOW_SIZE_FF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_MAX_FRAME_SIZE]")
        self.send_data([http2.setting(SETTINGS_MAX_FRAME_SIZE = b"\x00\x00\xFF\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_MAX_HEADER_LIST_SIZE]")
        self.send_data([http2.setting(SETTINGS_MAX_HEADER_LIST_SIZE = b"\x00\x00\xFF\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        
    def test_case13(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        SETTINGS_ENABLE_PUSH (0x2): Any value other than 0 or 1 MUST be treated as a connection error

        """

        print("[ TEST CASE 13 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_ENABLE_PUSH_0]")
        self.send_data([http2.setting(SETTINGS_ENABLE_PUSH = b"\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("> [SETTINGS_SETTINGS_ENABLE_PUSH_1]")
        self.send_data([http2.setting(SETTINGS_ENABLE_PUSH = b"\x00\x00\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_ENABLE_PUSH_FF]")
        self.send_data([http2.setting(SETTINGS_ENABLE_PUSH = b"\x00\x00\x00\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("> [SETTINGS_SETTINGS_ENABLE_PUSH_MAX]")
        self.send_data([http2.setting(SETTINGS_ENABLE_PUSH = b"\xff\xff\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_SETTINGS_ENABLE_PUSH_RANDOM")
        self.send_data([http2.setting(SETTINGS_ENABLE_PUSH = b"\x01\x02\x03\x04")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        
    def test_case14(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        A value of 0 for SETTINGS_MAX_CONCURRENT_STREAMS SHOULD NOT be treated as special by endpoints. 

        """

        print("[ TEST CASE 14 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_CONCURRENT_STREAMS_1]")
        self.send_data([http2.setting(SETTINGS_MAX_CONCURRENT_STREAMS = b"\x00\x00\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_CONCURRENT_STREAMS_0]")
        self.send_data([http2.setting(SETTINGS_MAX_CONCURRENT_STREAMS = b"\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_CONCURRENT_STREAMS_MAX]")
        self.send_data([http2.setting(SETTINGS_MAX_CONCURRENT_STREAMS = b"\xFF\xFF\xFF\xFF")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        

    def test_case15(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        SETTINGS_INITIAL_WINDOW_SIZE (0x4): Values above the maximum flow-control window size of 231-1 MUST be treated as a connection error (Section 5.4.1) of type FLOW_CONTROL_ERROR.

        """

        print("[ TEST CASE 15 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_INITIAL_WINDOW_SIZE_0]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_INITIAL_WINDOW_SIZE_1]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_INITIAL_WINDOW_SIZE_FF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_INITIAL_WINDOW_SIZE_FFFF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_INITIAL_WINDOW_SIZE_FFFFFF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\xff\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("> [SETTINGS_INITIAL_WINDOW_SIZE_FFFFFFFF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\xff\xff\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        
        print("> [SETTINGS_INITIAL_WINDOW_SIZE_0]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case16(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        SETTINGS_MAX_FRAME_SIZE (0x5): The initial value is 2^14 (16,384) octets. The value advertised by an endpoint MUST be between this initial value and the maximum allowed frame size (224-1 or 16,777,215 octets), inclusive. Values outside this range MUST be treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.

        """

        print("[ TEST CASE 16 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_FRAME_SIZE_FFFF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_FRAME_SIZE_FFFFFF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\xff\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_FRAME_SIZE_1]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\x01")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_MAX_FRAME_SIZE_FFFFFFFF]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\xff\xff\xff\xff")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))                
        
        print("> [SETTINGS_MAX_FRAME_SIZE_0]")
        self.send_data([http2.setting(SETTINGS_INITIAL_WINDOW_SIZE = b"\x00\x00\x00\x00")])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))        

    def test_case17(self):
        """

        http://httpwg.org/specs/rfc7540.html#SETTINGS
        An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST ignore that setting.

        """

        print("[ TEST CASE 17 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS_UNKNOWN_PARAM]")
        self.send_data([http2.setting(payload = b"\x00\x07\xff\xff\xff\xff"*100)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case18(self):
        """

        http://httpwg.org/specs/rfc7540.html#PUSH_PROMISE
        A PUSH_PROMISE frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame for the same stream.

        """

        print("[ TEST CASE 18 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PUSH_PROMISE]")
        self.send_data([http2.push_promise(END_HEADERS = False)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

    def test_case19(self):
        """

        http://httpwg.org/specs/rfc7540.html#StreamStates
        """

        print("[ TEST CASE 19 ]----------------------------------")
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [SETTINGS]")
        self.send_data([http2.setting()])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [HEADERS]")


        small_get_index_html_header = {
            ":method" : "GET",
            ":scheme" : "http",
            ":path" : "/index.html",
            ":authority": "localhost",
            "host" : "localhost"   
        }

        header_data = Encoder().encode(small_get_index_html_header, huffman=False)
        
        self.send_data([http2.headers(END_HEADERS = True, header_block_fragment = header_data)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))

        print("> [PUSH_PROMISE]")
        self.send_data([http2.push_promise(END_HEADERS = False)])
        data = self.__read_from_socket()
        print("< {}".format(self.__parse_client_request(data)))
        


        
    def init_target(self):
        """This method waits for the initial HTTP request sent by the target.
        It answers with our dedicated JS page"""

        if "h2" not in self.client_socket.selected_alpn_protocol():
            raise Exception("Client did not request http2 via ALPN")

        print("[+] Client negotiated HTTP2 via ALPN")

        client_preface = self.client_socket.recv(24)
        if client_preface == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
            print("[+] Client sent its preface")
        else:
            raise Exception("Client didn't send its preface")
        

        return

    def __read_from_socket(self, timeout = 0.5):
        """This method keep reading from the socket for data till a decent timeout occurs"""
        
        received_data = b''
        buf = ''
        
        self.client_socket.setblocking(0)
        try:

            start_time = time.time()
            while True:
                
                # if you got some data, then break after timeout
                if received_data and time.time() - start_time > timeout:
                    break
         
                # if you got no data at all, wait a little longer, twice the timeout
                elif time.time() - start_time > timeout * 2:
                    break
         
                #recv something
                try:
                    buf = self.client_socket.recv(8192)
                    if buf:
                        received_data += buf
                        #change the beginning time for measurement
                        start_time = time.time()
                    else:
                        #sleep for sometime to indicate a gap
                        time.sleep(0.1)
                except:
                    pass
        finally:
            self.client_socket.setblocking(1)                
        
        return received_data
    

    def send_data(self, datas):
        data_values = b''
        for data_value in datas:
            data_values += data_value
        print(data_values)
        self.client_socket.send(data_values)
        
        # # lets send an empty setting
        # empty_setting = http2.setting()
        # print("Sending EMPTY SETTING: {}".format(empty_setting))

        # #self.client_socket.send(empty_setting)
        # print("Empty setting sent to the client")

        # print("Waiting for the initial client request")
        # while True:
        #     initial_request = self.__read_from_socket()
        #     print("Received {} bytes".format(len(initial_request)))
        #     print(repr(initial_request))

    def __parse_client_request(self, data):
        symbols = []
        for message in self.split_flow_in_messages(data):
            found = False
            for symbol in http2.vocabulary():
                parser = MessageParser()
                try:
                    alignments = parser.parseMessage(RawMessage(message), symbol)

                    field_values = self.__parse_symbol(symbol, alignments)
                    
                    symbols.append((symbol.name, field_values))
                    found = True
                    break
                except Exception as e:
                    pass

            if not found:
                symbols.append(message)

        self.io_symbols.append(symbols)
        return symbols

    def __parse_symbol(self, symbol, alignments):
                            
        field_values = {}

        for i_field, field in enumerate(symbol.getLeafFields()):
            if i_field >= 4:                            
                field_values[field.name] = str(TypeConverter.convert(alignments[i_field], BitArray, Raw))
        

        if symbol.name == "SETTINGS":

            payload = TypeConverter.convert(alignments[4], BitArray, Raw)

            for i_val in range(0, len(payload), 6):
                val_type = payload[i_val:i_val+2]
                val_val = payload[i_val+2:i_val+6]
                if val_type == b"\x00\x01":                    
                    field_values['SETTINGS_HEADER_TABLE_SIZE'] = struct.unpack('>I', val_val)[0]
                elif val_type == b"\x00\x02":                    
                    field_values['SETTINGS_ENABLE_PUSH'] = struct.unpack('>I', val_val)[0]
                elif val_type == b"\x00\x03":                    
                    field_values['SETTINGS_MAX_CONCURRENT_STREAMS'] = struct.unpack('>I', val_val)[0]
                elif val_type == b"\x00\x04":                    
                    field_values['SETTINGS_INITIAL_WINDOW_SIZE'] = struct.unpack('>I', val_val)[0]
                elif val_type == b"\x00\x05":                    
                    field_values['SETTINGS_MAX_FRAME_SIZE'] = struct.unpack('>I', val_val)[0]
                elif val_type == b"\x00\x06":                    
                    field_values['SETTINGS_MAX_HEADER_LIST_SIZE'] = struct.unpack('>I', val_val)[0]

        if symbol.name == "WINDOW_UPDATE":
            payload = TypeConverter.convert(alignments[4], BitArray, Raw)
            field_values['Window Size Increment'] = struct.unpack('>I', payload)[0]

        return field_values

    def split_flow_in_messages(self, data):

        remaining_data = data
        while len(remaining_data) > 0:
            l = b"\x00"+remaining_data[:3]
            size = struct.unpack(">I", l)[0]
            frame_size = size + 9
            yield remaining_data[:frame_size]
            remaining_data = remaining_data[frame_size:]
        

        
        # symbols = []

        # try:
        #     flow_parser = FlowParser(memory = Memory())
        #     parsing_path = flow_parser.parseFlow(RawMessage(data), http2.vocabulary())
        #     field_values = []
        #     for symbol, alignments in parsing_path:
        #         # for i_f, f in enumerate(symbol.getLeafFields()):
        #         #    field_values.append((f.name, TypeConverter.convert(alignments[i_f], BitArray, Raw)))
        #         symbols.append((symbol, field_values))

        # except Exception as e:
        #     print(e)
            
        # return symbols

    def __send_file_to_client(self, file_path):
        """This method sends the specified file in http"""

        file_content = ""
        with open(file_path) as fd:
            file_content = fd.read()
        
        response = """HTTP/1.0 200 OK
Server: unknown
Content-type: text/html; charset=UTF-8
{}
""".format(file_content)

        self.client_socket.sendall(response.encode("utf-8"))
        
        
            
            
def build_socket(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))

    # build the ssl context
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.check_hostname = False
    context.load_default_certs()
    context.load_cert_chain(certfile = 'ssl_certs/localhost.pem')
    context.verify_mode = ssl.CERT_NONE

    context.set_alpn_protocols(["h2"])

    ssl_socket = context.wrap_socket(server_socket, server_side=True)
    return ssl_socket

def main(nb_listen_ports = 100):
    test_manager = TestManager()

    threads = []
    for port in range(8001, 8001+nb_listen_ports):
        t = Thread(target = listen, args=(test_manager, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    

def listen(test_manager, port=8001):
    
    s = build_socket(port)    
    s.listen(10)
    print("Listening on {}".format(port))

    output_path = "./results"

    locks = dict()
    while True:
        try:
            newsock, (remhost, remport) = s.accept()

            if remhost not in locks.keys():
                locks[remhost] = Lock()
            ip_lock = locks[remhost]
        
            client_handler = ClientHandler(port, newsock, (remhost, remport), test_manager, output_path, ip_lock)
            client_handler.start()
            CONNECTED_SOCKETS.append(newsock)
        except Exception as e:
            print("OUPS; {}".format(e))
        
    

if __name__ == "__main__":
    main()
