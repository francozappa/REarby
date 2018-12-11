"""
validation.py

    input validation


"""

from constants import *
from ecc import *

def validate_iv(name, iv):
    emsg1 = "{} type(iv): {}. It should be bytes".format(name, type(iv))
    assert type(iv) == bytes, emsg1
    emsg2 = "{} len(iv): {}. It should be {}".format(name, len(iv), AES_IV_BYTES)
    assert len(iv) == AES_IV_BYTES, emsg2


def validate_aes256_key(name, key):
    emsg1 = "{} type(key): {}. It should be bytes".format(name, type(key))
    assert type(key) == bytes, emsg1
    emsg2 = "{} len(key): {}. It should be {}".format(name, len(key), AES_KEY_BYTES)
    assert len(key) == AES_KEY_BYTES, emsg2


def validate_pt_type(name, pt_type):
    emsg1 = "{} pt_type: {} is not in {}".format(name, pt_type, NC_PT_TYPES)
    assert pt_type in NC_PT_TYPES, emsg1


def validate_pt(name, pt):
    emsg1 = "{} type(pt): {}. It should be bytes".format(name, type(pt))
    assert type(pt) == bytes, emsg1


def validate_ct(name, ct):
    emsg1 = "{} type(pt): {}. It should be bytes".format(name, type(ct))
    assert type(ct) == bytes, emsg1
    emsg2 = "{} len(pt): {}. It should be multiple of {}".format(name, len(ct),
        AES_BLOCK_BYTES)
    assert len(ct) % AES_BLOCK_BYTES == 0, emsg2


def validate_shared_secret(name, shared_secret):
    emsg1 = "{} type(shared_secret): {}. It should be bytes".format(name,
            type(shared_secret))
    assert type(shared_secret) == bytes, emsg1
    emsg2 = "{} len(shared_secret): {}. It should be 32".format(name,
            len(shared_secret))
    assert len(shared_secret) == 32, emsg2


def validate_kep2(name, kep2):
    emsg1 = "{} type(kep2): {}. It should be bytes".format(name, type(kep2))
    assert type(kep2) == bytes, emsg1
    # NOTE: 140 and 121 might have some delta
    emsg2 = "{} len(kep2): {}. It should be 140".format(name, len(kep2))
    assert len(kep2) == 140, emsg2


def validate_kep3(name, kep3):
    emsg1 = "{} type(kep3): {}. It should be bytes".format(name, type(kep3))
    assert type(kep3) == bytes, emsg1
    # NOTE: 140 and 121 might have some delta
    emsg2 = "{} len(kep3): {}. It should be in 120-122".format(name, len(kep3))
    assert (len(kep3) == 120 or len(kep3) == 121 or len(kep3) == 122), emsg2


def validate_kep4(name, kep4):
    emsg1 = "{} type(kep4): {}. It should be bytes".format(name, type(kep4))
    assert type(kep4) == bytes, emsg1


def validate_pri_key(name, pri_key):
    emsg1 = "{} type(pri_key): {}. It should be bytes".format(name, type(pri_key))
    assert type(pri_key) == bytes, emsg1

def validate_pub_key(name, pub_key):
    """Not validating if it is on the curve."""

    emsg1 = "{} type(pub_key): {}. It should be tuple".format(name, type(pub_key))
    assert type(pub_key) == tuple, emsg1

    emsg2 = "{} len(pub_key): {}. It should be 2".format(name, type(pub_key))
    assert len(pub_key) == 2, emsg2

def validate_int(name, _int):
    emsg1 = "{} type(_int): {}. It should be int".format(name, type(_int))
    assert type(_int) == int, emsg1


def validate_str(name, _str):
    emsg1 = "{} type(_str): {}. It should be str".format(name, type(_str))
    assert type(_str) == str, emsg1


def validate_bytes(name, _bytes):
    emsg1 = "{} type(_bytes): {}. It should be bytes".format(name, type(_bytes))
    assert type(_bytes) == bytes, emsg1


def validate_point(name, point):
    """Point should be on the secp256r1 curve."""

    emsg1 = "{} type(point[0]): {}. It should be bytes".format(name, type(point[0]))
    assert  type(point[0]) == bytes, emsg1
    emsg2 = "{} len(point[0]): {}. It should be 32 or 33".format(name, len(point[0]))
    assert len(point[0]) in POINT_LENS_BYTES, emsg2

    emsg3 = "{} type(point[1]): {}. It should be bytes".format(name, type(point[1]))
    assert  type(point[1]) == bytes, emsg3
    emsg4 = "{} len(point[1]): {}. It should be 32 or 33".format(name, len(point[1]))
    assert len(point[1]) in POINT_LENS_BYTES, emsg4

    point_int = (bytes_to_int(point[0]), bytes_to_int(point[1]))
    emsg5 = "{} point {} is not on the secp256r1 curve".format(name, point)
    assert  is_on_curve(point_int), emsg5


def validate_strategy(name, strategy):
    """Strategy should be either P2P_STAR or P2P_CLUSTER."""
    emsg1 = "{} strategy: {}. It should be either P2P_STAR or P2P_CLUSTER".format(
        name, strategy)
    assert strategy == 'P2P_STAR' or strategy == 'P2P_CLUSTER', emsg1


def validate_ip(name, ip):
    """IP is a list of 4 bytes."""
    emsg1 = "{} type(ip): {}. It should be list".format(name, type(ip))
    assert type(ip) == bytes, emsg1
    emsg2 = "{} len(ip): {}. It should be 4".format(name, type(ip))
    assert len(ip) == 4, emsg2
    for num in ip:
        emsg3 = "{} type(num): {}. It should be int".format(name, type(num))
        assert type(num) == int, emsg3


def validate_tcp_port(name, tcp_port):
    """TCP port are 3 bytes."""
    emsg1 = "{} type(tcp_port): {}. It should be bytes".format(name,
            type(tcp_port))
    assert type(tcp_port) == bytes, emsg1
    emsg2 = "{} len(tcp_port): {}. It should be 3".format(name, len(tcp_port))
    assert len(tcp_port) == 3, emsg2


def validate_essid(name, essid):
    """Direct AP has a variable length essid."""
    emsg1 = "{} type(essid): {}. It should be bytes".format(name, type(essid))
    assert type(essid) == bytes, emsg1
    emsg2 = "{} len(essid): {}. It should be 28 (hostapd) or contain DIRECT-".format(
        name, len(essid))
    assert len(essid) == 28 or essid.startswith('DIRECT-'), emsg2


def validate_password(name, password):
    emsg1 = "{} type(password): {}. It should be bytes".format(name,
        type(password))
    assert type(password) == bytes, emsg1
    emsg2 = "{} len(password): {}. It should be 12 (hostapd) or 8 (direct)".format(
        name, len(password))
    assert len(password) == 12 or len(password) == 8, emsg2


def validate_wifi_mode(name, wifi_mode):
    emsg1 = "{} {} not in {}".format(name, wifi_mode, WIFI_MODES)
    assert wifi_mode in WIFI_MODES
