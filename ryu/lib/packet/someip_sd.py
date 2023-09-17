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

class someip_sd_entry:
    # _SOMEIP_SD_ENTRY = '!BBBBHHBBBBI'
    def __init__(self, entry_type, idx1_options, idx2_options, opt_cnt,
                       service_id, instance_id
                       major_version, ttl1, ttl2, ttl3, minor_version):
        self.entry_type = entry_type
        self.idx1_options = idx1_options
        self.idx2_options = idx2_options
        self.opt1_cnt = opt_cnt >> 4 & 0x0F   # upper 4bit
        self.opt2_cnt = opt_cnt & 0x0F  # lower 4bit
        self.major_version = major_version
        self.TTL = (ttl1<<16 | ttl2<<8 | ttl3) & 0x0FFF
        self.minor_version = minor_version


class someip_sd_option:
    # _SOMEIP_SD_OPTION = '!HBBIBBH'
    def __init__(self, length, option_type, reserved1,
                       ipv4_addr,
                       reserved2, L4_proto, port_num):
        self.length = length
        self.option_type = option_type
        self.reserved1 = reserved1
        self.DFI = reserved1 >> 7 & 0x01
        self.ipv4_addr = ipv4_addr
        self.reserved2 = reserved2
        self.L4_proto = L4_proto
        self.port_num = port_num


class someip_sd(packet_base.PacketBase):
    """SOME/IP Service Discovery header encoder/decoder class.

    ========================= ====================
     Attribute                 Description
    ========================= ====================
    flags                     SOME/IP-SD Flags(8bit)
    reserved                  SOME/IP-SD Reserved(24bit)
    length_of_entries_array   SOME/IP-SD length of entries array
    entries_array             SOME/IP-SD entries array
    length_of_options_array   SOME/IP-SD length of options array
    entries_array             SOME/IP-SD options array
    ========================= ====================
    """

    # flag[8bit], reserved[24bit]
    # length of entries array [32bit]
    # entries array (1 entry size is 16byte)
    # length of options array [32bit]
    # options array (1 option size is 12byte)
    _SOMEIP_SD_HEADER_01 = '!BBBB'
    _SOMEIP_SD_HEADER_01_LEN = struct.calcsize(_SOMEIP_SD_HEADER_01)

    _SOMEIP_SD_LEN_OF_ENTRY = '!I'
    _SOMEIP_SD_LEN_OF_ENTRY_LEN = struct.calcsize(_SOMEIP_SD_LEN_OF_ENTRY)

    # TODO
    _SOMEIP_SD_ENTRY = '!BBBBHHBBBBI'
    _SOMEIP_SD_ENTRY_LEN = struct.calcsize(_SOMEIP_SD_ENTRY)

    _SOMEIP_SD_LEN_OF_OPTION = '!I'
    _SOMEIP_SD_LEN_OF_OPTION_LEN = struct.calcsize(_SOMEIP_SD_LEN_OF_OPTION)

    # TODO
    _SOMEIP_SD_OPTION = '!HBBIBBH'
    _SOMEIP_SD_OPTION_LEN = struct.calcsize(_SOMEIP_SD_OPTION)

    entry_type_tr_dict = {
        0x00 : "FIND",
        0x01 : "OFFER",
    }

    option_type_tr_dict = {
        0x00 : "FIND",
        0x01 : "OFFER",
    }

    def __init__(self, ):
        # TODO
        super(someip_sd, self).__init__()
        self.entries = []
        self.options= []
        self.entry_cnt = len(self.entries)
        self.option_cnt = len(self.options)

    def __repl__():
        msg = f"SOME/IP-SD packet(entry_cnt={self.entry_cnt}, option_cnt={self.option_cnt})"
        for i, entry in enumerate(self.entries, 1):
            msg += f"[{i}] Type={entry.type}, service_id={entry.service_id}, instance_id={entry.instance_id}"
        print(msg)

    @classmethod
    def parser(cls, buf):
        # [1] flags, reserved
        someip_sd_header1 = struct.unpack_from(cls._SOMEIP_SD_HEADER_01, buf)
        someip_sd_msg = cls(*someip_sd_header1)
        buf = buf[msg._SOMEIP_SD_HEADER_01_LEN:]

        # [2-1] length of entries
        entry_cnt = struct.unpack_from(cls._SOMEIP_SD_LEN_OF_ENTRY, buf)
        buf = buf[msg._SOMEIP_SD_LEN_OF_ENTRY_LEN:]
        someip_sd_msg.entry_cnt = entry_cnt

        # [2-2] entry
        # _SOMEIP_SD_ENTRY = '!BBBBHHBBBBI'
        for _ in range(entry_cnt/16):
            someip_sd_entry_tup = struct.unpack_from(cls._SOMEIP_SD_ENTRY, buf)
            someip_sd_msg.add_entry(someip_sd_entry(*someip_sd_entry_tup))
            buf = buf[msg._SOMEIP_SD_ENTRY_LEN:]

        # [3-1] length of options
        option_cnt = struct.unpack_from(cls._SOMEIP_SD_LEN_OF_OPTION, buf)
        buf = buf[msg._SOMEIP_SD_LEN_OF_ENTRY_LEN:]
        someip_sd_msg.option_cnt = option_cnt

        # [3-2] option
        # _SOMEIP_SD_OPTION = '!HBBIBBH'
        for _ in range(option_cnt/12):
            someip_sd_option_tup = struct.unpack_from(cls._SOMEIP_SD_OPTION, buf)
            someip_sd_msg.add_option(someip_sd_option(*someip_sd_option_tup))
            buf = buf[msg._SOMEIP_SD_OPTION_LEN:]

        return someip_sd_msg, None, None

