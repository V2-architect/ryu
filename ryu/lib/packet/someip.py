# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import logging

from . import packet_base
import pdb

LOG = logging.getLogger(__name__)

class someip(packet_base.PacketBase):
    """SOME/IP header encoder/decoder class.

    ============== ====================
    Attribute      Description
    ============== ====================
    service_id     SOME/IP service ID
    method_id      SOME/IP method ID
    length         SOME/IP payload length
    client_id      SOME/IP client ID
    session_id     SOME/IP session ID
    protocol_ver   SOME/IP protocol version
    intf_ver       SOME/IP interface version
    msg_type       SOME/IP message type
    ret_code       SOME/IP return code
    ============== ====================
    """

    _PACK_STR = '!HHIHHBBBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    msg_type_tr_dict = {
        0x00 : "REQUEST",
        0x01 : "REQUEST_NO_RETURN",
        0x02 : "NOTIFICATION",
        0x40 : "REQUEST_ACK",
        0x41 : "REQUEST_NO_RETURN_ACK",
        0x42 : "NOTIFICATION_ACK",
        0x80 : "RESPONSE",
        0x81 : "Error",
        0xC0 : "RESPONSE_ACK",
        0xC1 : "ERROR_ACK",
        0xFF : "UNKNOWN",
    }

    ret_code_tr_dict = {
        0x00 : "E_OK",
        0x01 : "E_NOT_OK",
        0x02 : "E_WRONG_INTERFACE_VERSION",
        0x03 : "E_UNKNOWN_METHOD",
        0x04 : "E_NOT_READY",
        0x05 : "E_NOT_REACHABLE",
        0x06 : "E_TIMEOUT",
        0x07 : "E_WRONG_PROTOCOL_VERSION",
        0x08 : "E_WRONG_INTERFACE_VERSION",
        0x09 : "E_MALFORMED_MESSAGE",
        0x0A : "E_WRONG_MESSAGE_TYPE",
        0xFF : "E_UNKNOWN",
    }

    def __init__(self, msg_id, method_id, length, client_id, sess_id, protocol_ver, intf_ver, msg_type_num, ret_code):
        super(someip, self).__init__()
        self.msg_id = msg_id
        self.method_id = method_id
        self.length = length
        self.client_id = client_id
        self.sess_id = sess_id
        self.protocol_ver = protocol_ver
        self.intf_ver = intf_ver
        self.msg_type_num = msg_type_num
        self.msg_type_str = self.get_msg_str(msg_type_num)
        self.ret_code = ret_code

    def get_msg_str(self, msg_type_num):
        return self.msg_type_tr_dict.get(msg_type_num, "WRONG_MSG_TYPE, " + str(msg_type_num))

    def __repl__():
        print(f"SOME/IP packet(msg_id={self.msg_id}, method_id={self.method_id}, length={self.length}, \
                client_id={self.client_id}, sess_id={self.sess_id}, protocol_ver={self.protocol_ver}, \
                intf_ver={self.intf_ver}, msg_type={self.msg_type_str}, ret_code={self.ret_code}")

    @classmethod
    def parser(cls, buf):
        someip_elems = struct.unpack_from(cls._PACK_STR, buf)
        msg = cls(*someip_elems)
        return msg, None, None
