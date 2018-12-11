"""
nc,py

Dissectors for the NC protocol. See an example of dissection in the dissect.py
script that uses packets from packets.py.

"""

from base64 import b64encode as b64e
from base64 import b64decode as b64d

from constants import *
from scapy.all import *


# NOTE: Helpers
def ip_to_int(a, b, c, d):
    """ Returns an integer

    For example 192.168.43.43 returns 3232246571
    """

    rv = (a * 16777216) + (b * 65536) + (c * 256) + (d)

    return rv


assert ip_to_int(192, 168, 43, 43) == 3232246571


# NOTE: Tests
class StrStopFieldB64Decoded(StrStopField):
    """NCload is 64 decoded."""

    def h2i(self, pkt, x):
        return b64encode(plain_str(x).encode())

    def i2h(self, pkt, x):
        return b64encode(x)


class TestBit(Packet):
    fields_desc=[
        BitFieldLenField("len1", None, size=8, length_of="data"),
        StrLenField("data", "", length_from=lambda pkt:pkt.len1),
    ]



# NOTE: KEP
class Kep1V2(Packet):
    version = b"\x02"
    name = "Kep1: dsc -> adv"
    fields_desc = [
        IntField("len1", None),
        XByteField("sep1", 0x08),
        ByteField("sn", 1),
        XByteField("NC_SEP", NC_SEP),
        ByteField("len2", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len3", None),
        XByteField("NEWLINE", NEWLINE),
        ByteField("eid_len", EID_LEN),
        StrFixedLenField("eid", "abcd", EID_LEN),
        XByteField("sep3", NC_SEP),
        BitFieldLenField("ncname_len", None, size=8, length_of="ncname"),
        StrLenField("ncname", "", length_from=lambda pkt:pkt.ncname_len),
        XByteField("SPACE", SPACE),
        StrStopField("str1", None, stop=b"("),
        StrField("version", version),
    ]

class Kep1(Packet):
    """I'm not sure about a and strategy.
    
    they do not change if I change the device."""
    version = b"\x04"
    name = "Kep1: dsc -> adv"
    fields_desc = [
        IntField("len1", None),
        XByteField("sep1", 0x08),
        ByteField("sn", 1),
        XByteField("NC_SEP", NC_SEP),
        ByteField("len2", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len3", None),
        XByteField("NEWLINE", NEWLINE),
        ByteField("eid_len", EID_LEN),
        StrFixedLenField("eid", "abcd", EID_LEN),
        XByteField("sep3", NC_SEP),
        BitFieldLenField("ncname_len", None, size=8, length_of="ncname"),
        StrLenField("ncname", "", length_from=lambda pkt:pkt.ncname_len),
        XByteField("SPACE", SPACE),
        # StrStopField("a", None, stop=b"("),
        # StrStopField("strategy", None, stop=b"\x02("),
        # StrField("version", version),
    ]


class Kep2(Packet):
    name = "Kep2: dsc -> adv"
    fields_desc = [
        IntField("len1", None),
        XByteField("sep1", 0x08),
        ByteField("sn", 2),
        XByteField("NC_SEP", 0x12),
        ByteField("len2", None),
        ByteField("count2", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        BitFieldLenField("kdf1_len", None, size=8, length_of="kdf1"),
        StrLenField("kdf1", "", length_from=lambda pkt:pkt.kdf1_len),
        XByteField("SUBSTITUTE", SUBSTITUTE),
        ByteField("len3", None),
        StrFixedLenField("NC_KEP2_HEAD", NC_KEP2_HEAD, length=2),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("kdf2_len", None, size=8, length_of="kdf2"),
        StrLenField("kdf2", "", length_from=lambda pkt:pkt.kdf2_len),
        StrFixedLenField("DQUOTE", '"', length=1),
        BitFieldLenField("algo_len", 23, size=8, length_of="algo"),
        StrLenField("algo", "AES_256_CBC-HMAC_SHA256",
            length_from=lambda pkt:pkt.algo_len),
    ]


class Kep3(Packet):
    name = "Kep3: adv -> dsc"
    fields_desc = [
        IntField("len1", None),
        XByteField("sep1", 0x08),
        ByteField("sn", 3),
        XByteField("NC_SEP", NC_SEP),
        ByteField("len2", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        BitFieldLenField("kdf_len", None, size=8, length_of="kdf"),
        StrLenField("kdf", "", length_from=lambda pkt:pkt.kdf_len),
        StrFixedLenField("NC_KEP3_HEAD", NC_KEP3_HEAD, length=3),
        ByteField("len3", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len4", None),
        XByteField("NEWLINE", NEWLINE),
        BitFieldLenField("xA_len", None, size=8, length_of="xA"),
        StrLenField("xA", "", length_from=lambda pkt:pkt.xA_len),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("yA_len", None, size=8, length_of="yA"),
        StrLenField("yA", "", length_from=lambda pkt:pkt.yA_len),
    ]

class Kep4(Packet):
    name = "Kep4: dsc -> adv"
    str4_len = 1
    fields_desc = [
        IntField("len1", None),
        XByteField("sep1", 0x08),
        ByteField("sn", 4),
        XByteField("NC_SEP", NC_SEP),
        ByteField("len2", None),
        XByteField("NEWLINE", NEWLINE),
        ByteField("len3", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len4", None),
        XByteField("NEWLINE", NEWLINE),
        BitFieldLenField("xD_len", None, size=8, length_of="xD"),
        StrLenField("xD", "", length_from=lambda pkt:pkt.xD_len),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("yD_len", None, size=8, length_of="yD"),
        StrLenField("yD", "", length_from=lambda pkt:pkt.yD_len),
    ]


# NOTE: Payloads
class Pay(Packet):
    """
    Each byte payload always generates Pay and Pay2 in sequence.

    Pay is 120 Bytes and contains a 32 bytes ct. The respective pt contains
    the NC message.

    """
    name = "Pay"
    fields_desc = [
        IntField("len1", None),
        XByteField("NEWLINE", NEWLINE),
        ByteField("d_len+var4", None),
        XByteField("NEWLINE", NEWLINE),
        StrFixedLenField("NC_HEAD", NC_HEAD, length=6),
        BitFieldLenField("iv_len", None, size=8, length_of="iv"),
        StrLenField("iv", "", length_from=lambda pkt:pkt.iv_len),
        ByteField("len2", None),
        BitFieldLenField("var2", None, size=8, length_of="todo2"),
        StrLenField("todo2", b"\x08\r\x10\x01", length_from=lambda pkt:pkt.var2),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("ct_len", None, size=8, length_of="ct"),
        StrLenField("ct", "", length_from=lambda pkt:pkt.ct_len),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("mac_len", None, size=8, length_of="mac"),
        StrLenField("mac", "", length_from=lambda pkt:pkt.mac_len),
    ]


class Pay2(Packet):
    """
    Each byte payload always generates Pay and Pay2 in sequence.

    Pay2 is 120 Bytes and its pt has a fixed length (see NC_PAY2_*)

    """
    name = "Pay2"
    fields_desc = [
        IntField("len1", None),
        XByteField("NEWLINE", NEWLINE),
        ByteField("d_len+var4", None),
        XByteField("NEWLINE", NEWLINE),
        StrFixedLenField("NC_HEAD", NC_HEAD, length=6),
        BitFieldLenField("iv_len", None, size=8, length_of="iv"),
        StrLenField("iv", "", length_from=lambda pkt:pkt.iv_len),
        ByteField("len2", None),
        BitFieldLenField("var2", None, size=8, length_of="todo2"),
        StrLenField("todo2", b"\x08\r\x10\x01", length_from=lambda pkt:pkt.var2),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("ct_len", None, size=8, length_of="ct"),
        StrLenField("ct", "", length_from=lambda pkt:pkt.ct_len),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("mac_len", None, size=8, length_of="mac"),
        StrLenField("mac", "", length_from=lambda pkt:pkt.mac_len),
    ]


class PayStream(Packet):
    """
    Stream payload are encapsulated differently than bytes and file.

    """
    name = "PayStream"
    fields_desc = [
        StrFixedLenField("NC_HEAD", NC_HEAD, length=30),
        BitFieldLenField("var", None, size=8, length_of="todo"),
        StrLenField("todo", None, length_from=lambda pkt:pkt.var),
        BitFieldLenField("var2", None, size=8, length_of="todo2"),
        StrLenField("todo2", None, length_from=lambda pkt:pkt.var2),
        BitFieldLenField("var3", None, size=8, length_of="todo3"),
        StrLenField("todo3", None, length_from=lambda pkt:pkt.var3),
        BitFieldLenField("var4", None, size=8, length_of="todo4"),
        StrLenField("todo4", None, length_from=lambda pkt:pkt.var4),
        BitFieldLenField("var5", None, size=8, length_of="todo5"),
        StrLenField("todo5", None, length_from=lambda pkt:pkt.var5),
        # ByteField("d_len+var4", None),
        # XByteField("NEWLINE", NEWLINE),
        # StrFixedLenField("NC_HEAD", NC_HEAD, length=6),
        # BitFieldLenField("iv_len", None, size=8, length_of="iv"),
        # StrLenField("iv", "", length_from=lambda pkt:pkt.iv_len),
        # ByteField("len2", None),
        # BitFieldLenField("var2", None, size=8, length_of="todo2"),
        # StrLenField("todo2", b"\x08\r\x10\x01", length_from=lambda pkt:pkt.var2),
        # XByteField("NC_SEP", NC_SEP),
        # BitFieldLenField("ct_len", None, size=8, length_of="ct"),
        # StrLenField("ct", "", length_from=lambda pkt:pkt.ct_len),
        # XByteField("NC_SEP", NC_SEP),
        # BitFieldLenField("mac_len", None, size=8, length_of="mac"),
        # StrLenField("mac", "", length_from=lambda pkt:pkt.mac_len),
    ]


class Eka(Packet):
    """Encrypted Keep Alive with metadata"""
    name = "Eka: dsc <-> adv"
    fields_desc = [
        IntField("len1", None),
        XByteField("NEWLINE", NEWLINE),
        ByteField("d_len+var4", None),
        XByteField("NEWLINE", NEWLINE),
        StrFixedLenField("NC_HEAD", NC_HEAD, length=6),
        BitFieldLenField("iv_len", None, size=8, length_of="iv"),
        StrLenField("iv", "", length_from=lambda pkt:pkt.iv_len),
        ByteField("len2", None),
        BitFieldLenField("var2", None, size=8, length_of="todo2"),
        StrLenField("todo2", b"\x08\r\x10\x01", length_from=lambda pkt:pkt.var2),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("ct_len", None, size=8, length_of="ct"),
        StrLenField("ct", "", length_from=lambda pkt:pkt.ct_len),
        XByteField("NC_SEP", NC_SEP),
        BitFieldLenField("mac_len", None, size=8, length_of="mac"),
        StrLenField("mac", "", length_from=lambda pkt:pkt.mac_len),
    ]


# NOTE: errors
class Error(Packet):
    """
    Useful to RE, don't know how to cause them.

    """
    name = "Error"
    fields_desc = [
        IntField("len1", None),
        StrFixedLenField("NC_ERR_HEAD", NC_ERR_HEAD, length=3),
        BitFieldLenField("e_len", None, size=8, length_of="emsg"),
        StrLenField("emsg", "", length_from=lambda pkt:pkt.e_len),
    ]



# NOTE: decrypted application layer
class KA(Packet):
    """
    Applicaiton layer decrypted keep alive

    a is either \x08\x052\x00 or \x08\x04*\x02\x08\x03

    """
    name = "KA"
    fields_desc = [
        XByteField("NEWLINE", NEWLINE),
        ByteField("len1", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        BitFieldLenField("a_len", None, size=8, length_of="a"),
        StrLenField("a", "", length_from=lambda pkt:pkt.a_len),
        XByteField("sep", b'\x10'),
        ByteField("count", None),
    ]

class WL(Packet):
    """
    WLAN packet containing the ip and tcp_port of the adv.


    """
    name = "WL: adv -> dsc"
    fields_desc = [
        XByteField("NEWLINE", NEWLINE),
        ByteField("len1", b'\x1a'),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len2", b'\x16'),
        StrFixedLenField("NC_HEAD4", NC_HEAD4, length=3),
        ByteField("len3", b'\x12'),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len4", b'\x0e'),
        StrFixedLenField("a", b'\x08\x05\x1a', length=3),
        XByteField("NEWLINE", NEWLINE),
        XByteField("NEWLINE", NEWLINE),
        BitFieldLenField("ip_len", None, size=8, length_of="ip"),
        StrLenField("ip", "", length_from=lambda pkt:pkt.ip_len),
        XByteField("sep1", b'\x10'),
        StrFixedLenField("tcp_port", None, length=3),
        XByteField("sep2", b'\x10'),
        ByteField("count", None),
    ]


class IW(Packet):
    """
    First packet sent from the dsc on WLAN after TCP handshake, 22 Bytes.

    It contains the eid of the dsc.
    """
    name = "IW: dsc --> adv"
    fields_desc = [
        IntField("len1", 0x12),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len2", 0xe),
        StrFixedLenField("NC_HEAD4", NC_HEAD4, length=3),
        ByteField("len3", 0xa),
        StrFixedLenField("NC_HEAD5", NC_HEAD5, length=3),
        ByteField("len4", 0x6),
        XByteField("NEWLINE", NEWLINE),
        BitFieldLenField("eid_len", 4, size=8, length_of="eid"),
        StrLenField("eid", "", length_from=lambda pkt:pkt.eid_len),
    ]

class SH(Packet):
    """SH"""
    name = "SH: adv <-> dsc"
    fields_desc = [
        XByteField("NEWLINE", NEWLINE),
        ByteField("len1", 0xa),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len2", 0x6),
        StrFixedLenField("NC_HEAD4", NC_HEAD4, length=3),
        ByteField("len3", 0x2),
        StrFixedLenField("a", None, length=2),
        XByteField("sep1", b'\x10'),
        ByteField("count", None),
    ]



class Pt(Packet):
    """

    Each byte payload always generates Pt and Pt2 in sequence that produce
    Pt and Pt2 cleartexts. Pt is longer than Pt2 (extra len4 and f fields).

        count depends on the direction of the packet
        pid is equal in couples of Pt-Pt2. It might be the payloadid
        ptype is 1 for Bytes and 2 for File.
        pay_len is the length of the carried plaintext
        pt_len is the length of the byte message


    """
    name = "Pt"
    fields_desc = [
        XByteField("NEWLINE", NEWLINE),
        ByteField("len1", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len2", None),
        StrFixedLenField("NC_HEAD3", NC_HEAD3, length=3),
        ByteField("len3", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        StrFixedLenField("c", None, length=2),
        StrFixedLenField("pid", None, length=9),
        StrFixedLenField("sep1", b'\x01\x10', length=2),
        ByteField("ptype", None),
        ByteField("sep2", b'\x18'),
        ByteField("pt_len", None),  # equals pay_len
        ByteField("sep3", SUBSTITUTE),
        ByteField("len4", None),
        StrStopField("f", None, stop=SUBSTITUTE),
        BitFieldLenField("pay_len", None, size=8, length_of="pay"),
        StrLenField("pay", "", length_from=lambda pkt:pkt.pay_len),
        XByteField("sep5", b'\x10'),
        ByteField("count", None),
    ]


class Pt2(Packet):
    """

    Each byte payload always generates Pay and Pay2 in sequence that produce
    Pt and Pt2 cleartexts. Pt2 is shorter than Pt (no len4 and f fields)

        pt_len and p
        See Pt doc


    """
    name = "Pt2"
    fields_desc = [
        XByteField("NEWLINE", NEWLINE),
        ByteField("len1", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len2", None),
        StrFixedLenField("NC_HEAD3", NC_HEAD3, length=3),
        ByteField("len3", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        StrFixedLenField("c", None, length=2),
        StrFixedLenField("pid", None, length=9),
        ByteField("sep3", b'\x01'),
        ByteField("len4", None),
        ByteField("ptype", None),
        ByteField("sep1", b'\x18'),
        ByteField("pt_len", None),  # equal to pt_len2
        ByteField("sep2", SUBSTITUTE),
        ByteField("pay_len", 4),
        StrFixedLenField("pay123", b'\x08\x01\x10', length=3),
        ByteField("pt_len2", None),  # equal to pt_len
        XByteField("sep", b'\x10'),
        ByteField("count", None),
    ]


class HA(Packet):
    """

    Adv sends this packet when the strategy is P2P_STAR and when
    the adv is not connected to the same AP of the dsc

        essid is the access point name
        password is the access point password
        tcp_port
        a, b, c, d are constants

    """
    name = "HA: adv -> dsc"
    fields_desc = [
        XByteField("NEWLINE", NEWLINE),
        ByteField("len1", None),
        StrFixedLenField("NC_HEAD2", NC_HEAD2, length=3),
        ByteField("len2", None),
        StrFixedLenField("b", None, length=3),
        ByteField("len3", None),
        StrFixedLenField("c", None, length=3),
        ByteField("len4", None),
        StrFixedLenField("d", None, length=3),
        ByteField("len5", None),
        XByteField("NEWLINE", NEWLINE),
        BitFieldLenField("essid_len", None, size=8, length_of="essid"),
        StrLenField("essid", "", length_from=lambda pkt:pkt.essid_len),
        XByteField("sep", b'\x12'),
        BitFieldLenField("password_len", None, size=8, length_of="password"),
        StrLenField("password", "", length_from=lambda pkt:pkt.password_len),
        XByteField("sep2", b'\x18'),
        StrFixedLenField("tcp_port", None, length=3),
        XByteField("sep3", b'\x10'),
        ByteField("count", None),
    ]


class Stream(Packet):
    """
    Stream is not authenticated


    """
    name = "Stream"
    fields_desc = [
        # ByteField("len1", None),
        # XByteField("NEWLINE", NEWLINE),
        # ByteField("len1", None),
        # BitFieldLenField("a_len", None, size=8, length_of="a"),
        # StrLenField("a", "", length_from=lambda pkt:pkt.a_len),
        # BitFieldLenField("b_len", None, size=8, length_of="b"),
        # StrLenField("b", "", length_from=lambda pkt:pkt.b_len),
    ]


class Stream2(Packet):
    """
    Stream2 should contain the message.


    """
    name = "Stream2"
    fields_desc = [
        # XByteField("NEWLINE", NEWLINE),
        # ByteField("len1", None),
        # BitFieldLenField("a_len", None, size=8, length_of="a"),
        # StrLenField("a", "", length_from=lambda pkt:pkt.a_len),
        # BitFieldLenField("b_len", None, size=8, length_of="b"),
        # StrLenField("b", "", length_from=lambda pkt:pkt.b_len),
    ]
