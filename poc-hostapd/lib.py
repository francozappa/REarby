from hashlib import md5, sha256

from base64 import b64decode, b64encode
from binascii import unhexlify

from random import randint
from os import urandom
from sys import exit
from time import sleep

from bluetooth import advertise_service
from bluetooth import discover_devices, find_service
from bluetooth import BluetoothSocket, RFCOMM, PORT_ANY
from bluetooth import SERIAL_PORT_CLASS, SERIAL_PORT_PROFILE
# from bluetooth.ble import DiscoveryService, BeaconService, GATTRequester

from cryptography.hazmat.backends            import default_backend
from cryptography.hazmat.primitives.hashes   import SHA256, Hash, SHA512
from cryptography.hazmat.primitives.hmac     import HMAC

from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers.algorithms import AES

from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.hazmat.primitives.serialization as ser

from ecc import *
from nc import *
from validation import *

import logging
log = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-4s %(levelname)-4s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)
# log.setLevel(logging.DEBUG)

SCAPY_KEP1_STAR_HA_TEMPLATE   = Kep1(NC_KEP1_STAR_HA_TEMPLATE)
SCAPY_KEP1_STAR_WD_TEMPLATE   = Kep1(NC_KEP1_STAR_WD_TEMPLATE)
SCAPY_KEP1_CLUS_TEMPLATE   = Kep1(NC_KEP1_CLUS_TEMPLATE)
SCAPY_KEP2_TEMPLATE   = Kep2(NC_KEP2_TEMPLATE)
SCAPY_KEP3_TEMPLATE   = Kep3(NC_KEP3_TEMPLATE)
SCAPY_KEP4_TEMPLATE   = Kep4(NC_KEP4_TEMPLATE)

SCAPY_KA_TEMPLATE     = KA(NC_KA_TEMPLATE)
SCAPY_EKA_TEMPLATE    = Eka(NC_EKA_TEMPLATE)

SCAPY_EWL_TEMPLATE    = Eka(NC_EWL_TEMPLATE)
SCAPY_WL_TEMPLATE     = WL(NC_WL_TEMPLATE)

SCAPY_EHA_TEMPLATE    = Eka(NC_EHA_TEMPLATE)
SCAPY_HA_TEMPLATE     = HA(NC_HA_TEMPLATE)

SCAPY_EWD_TEMPLATE    = Eka(NC_EWD_TEMPLATE)
SCAPY_WD_TEMPLATE     = HA(NC_WD_TEMPLATE)

SCAPY_SH_TEMPLATE      = SH(NC_SH_TEMPLATE)
SCAPY_SH2_TEMPLATE     = SH(NC_SH2_TEMPLATE)

SCAPY_IW_TEMPLATE     = IW(NC_IW_TEMPLATE)

SCAPY_PT_TEMPLATE     = Pt(NC_PT_TEMPLATE)
SCAPY_PAY_TEMPLATE    = Pay(NC_PAY_TEMPLATE)
SCAPY_PT2_TEMPLATE    = Pt2(NC_PT2_TEMPLATE)
SCAPY_PAY2_TEMPLATE   = Pay2(NC_PAY2_TEMPLATE)



def discover_bt(duration=1):
    """
    Discover NC devices using Bluetooth inquiry.

    :param duration: int

    :returns: list advs and others
    """
    validate_int('discover_bt', duration)

    advs = []
    others = []

    # NOTE: returns a list of tuples
    nearby_devices = discover_devices(duration, lookup_names=True)
    if len(nearby_devices) > 0:
        # log.debug("discover_bt found {} bt devices: {}".format(len(nearby_devices),
        #     nearby_devices))
        for addr, name in nearby_devices:
            if name.startswith('I') and name.find(BTNAME_SEP) != -1:
                adv = {"btaddr": addr, "btname": name}
                advs.append(adv)
                # log.debug("discover_bt advs append addr: {}, btname: {}".format(addr,
                #     name))
            else:
                other = {"btaddr": addr, "btname": name}
                others.append(other)
                log.debug("discover_bt others append addr: {}, btname: {}".format(addr,
                    name))

    else:
        log.debug("No BT devices found.")

    return advs, others


def get_adv_parameters(btname) -> dict:
    """
    Returns a dict of advertiser parameters

        :param btname: str

        :return: dict
    """
    validate_str('get_adv_parameters', btname)

    pars = {
        "strategy": '',
        "eid": '',
        "sid_sha256_03": b'',
        "name": '',
    }

    btname_padded = pad_b64(btname)
    btname_decoded = b64decode(btname_padded)
    # log.debug("get_adv_parameters btname_decoded: {}".format(btname_decoded))

    pars["strategy"] = chr(btname_decoded[0])
    # log.debug('get_adv_parameters pars["strategy"]: {}'.format(pars['strategy']))

    for i in range(1, 5):
        pars["eid"] += chr(btname_decoded[i])
    # log.debug('get_adv_parameters pars["eid"]: {}'.format(pars['eid']))

    pars["sid_sha256_03"] = btname_decoded[5:8]
    # log.debug('get_adv_parameters pars["repr(sid_sha256_digest)"]: {}'.format(
    #     repr(pars["sid_sha256_03"])))

    for i in btname_decoded[16:]:
        pars["name"] += chr(i)
    # log.debug('get_adv_parameters pars["name"]: {}'.format(pars['name']))

    return pars


def get_adv_btname(strategy, eid, name, sid) -> str:
    """
    Returns advertiser bluetooth's name

        :param strategy: str either '!' (P2P_STAR) or '"' (P2P_CLUSTER)
        :param eid: str
        :param name: str
        :param sid: str

        :return: bytes str btname unpadded
    """
    if type(eid) != str:
        log.error("get_adv_btname type(eid): {}. It should be str".format(type(eid)))
    if type(name) != str:
        log.error("get_adv_btname type(name): {}. It should be str".format(type(name)))
    if type(sid) != str:
        log.error("get_adv_btname type(sid): {}. It should be str".format(type(sid)))

    sid_sha256 = sha256()
    sid_sha256.update(sid.encode())
    sid_sha256_digest = sid_sha256.digest()[0:3]
    log.debug("get_adv_btname sid: {} sha256[0:3]: {}".format(sid,
        sid_sha256_digest))

    # NOTE: max name len is 131 (0x83)
    bl = [0 , 0 , 0, 0, 0 ,0 ,0]
    if len(name) > 131:
        name = name[:131]
    bl.append(len(name))
    separator = bytearray(bl)
    log.debug("get_adv_btname len: {} separator: {}".format(len(name),
        separator))

    b_btname  = b''
    b_btname  = strategy.encode('utf-8')
    b_btname += eid.encode('utf-8')
    b_btname += sid_sha256_digest
    # b_btname += b'\x00\x00\x00\x00\x00\x00\x00'
    b_btname += separator
    b_btname += name.encode()

    btname = b64encode(b_btname).decode()

    return unpad_b64(btname)


def pad_b64(encoded):
    """Append = or == to the b64 string."""
    if len(encoded) % 4 == 0:
        pass
    elif len(encoded) % 4 == 3:
        encoded += "="
    elif len(encoded) % 4 == 2:
        encoded += "=="

    return encoded


def unpad_b64(encoded):
    """Remove = or == from the end of the b64 string."""
    if encoded.find('=') != -1:
        return encoded[:encoded.find('=')]
    else:
        return encoded


def sid_to_uuid(sid) -> str:
    """
    Generate a valid NC uuid from a sid.

    :param sid: str

    :return: str

        eg: uuid = "b8c1a306-9167-347e-b503-f0daba6c5723"
    """
    validate_str('sid_to_uuid', sid)

    uuid = ''

    log.warning("sid_to_uuid: B9 not fully RE")

    sid_md5 = md5()
    sid_md5.update(sid.encode())
    sid_md5_hd = sid_md5.hexdigest()
    log.debug("sid_to_uuid sid_md5: {}".format(sid_md5_hd))

    uuid += sid_md5_hd[0:8]
    uuid += '-'
    uuid +=  sid_md5_hd[8:12]
    uuid += '-'
    uuid += '3'  # XX: always set to 3
    uuid +=  sid_md5_hd[13:16]
    uuid += '-'
    uuid +=  sid_md5_hd[16:20]
    uuid += '-'
    uuid +=  sid_md5_hd[20:]

    assert len(uuid) == 36
    log.debug("sid: {} fake uuid: {}".format(sid, uuid))

    return uuid



def nc_scapy_pkt(pt_type, fields) -> bytes:
    """
    Generates NC scapy packets,

    :param pt_type: string in NC_PT_TYPES
    :param fields: list content depends on pt_type

    :return: scapy packet

    kep1 fields:
        fields[0]: eid, str
        fields[1]: ncname, str
        fields[2]: strategy, str
        fields[3]: wifi_mode, str

    kep4 fields:
        fields[0]: pri_key, bytes
        fields[1]: pub_key, tuple of bytes

    kep2 fields:
        fields[0]: kep4, bytes

    kep3 fields:
        fields[0]: pri_key, bytes
        fields[1]: pub_key, tuple of bytes

    eka fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int

    ewl fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int
        fields[3]: ip, list
        fields[4]: tcp_port, bytes

    eha fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int
        fields[3]: essid, bytes, 28 or DIRECT-
        fields[4]: password, bytes, 12 or 8
        fields[5]: tcp_port, bytes, 3

    esh fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int

    esh2 fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int

    pay fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int
        fields[3]: pt, bytes
        fields[4]: pid, bytes

    pay2 fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int
        fields[3]: pay_len, int
        fields[4]: pid, bytes

    iw fields:
        fields[0]: key, bytes
        fields[1]: iv, bytes
        fields[2]: count, int
        fields[3]: eid, str

    """
    validate_pt_type("nc_scapy_pkt", pt_type)

    rv = b''


    if pt_type == 'kep1':
        eid  = fields[0]
        validate_str('nc_scapy_pkt kep1', eid)
        ncname = fields[1]
        validate_str('nc_scapy_pkt kep1', ncname)
        strategy = fields[2]
        validate_strategy('nc_scapy_pkt kep1', strategy)
        wifi_mode = fields[3]
        validate_wifi_mode('nc_scapy_pkt kep1', wifi_mode)

        # NOTE: use only latest version
        if strategy == 'P2P_STAR':
            if wifi_mode == 'hostapd':
                kep1_scapy = SCAPY_KEP1_STAR_HA_TEMPLATE
            elif wifi_mode == 'direct':
                kep1_scapy = SCAPY_KEP1_STAR_WD_TEMPLATE
        elif strategy == 'P2P_CLUSTER':
            kep1_scapy = SCAPY_KEP1_CLUS_TEMPLATE
        kep1_scapy.eid = eid
        kep1_scapy.ncname = ncname
        # NOTE: 4 depends on SCAPY_KEP1_TEMPLATE
        if len(ncname) != 4:
            delta = 4 - len(ncname)
            kep1_scapy.ncname_len = len(ncname)
            kep1_scapy.len1 -= delta
            kep1_scapy.len2 -= delta
            kep1_scapy.len3 -= delta
        # log.debug("nc_scapy_pkt kep1: {}".format(repr(kep1_scapy)))
        # log.debug("nc_scapy_pkt kep1_scapy.name: {}".format(kep1_scapy.name))

        rv = kep1_scapy

    elif pt_type == 'kep4':
        pri_key = fields[0]
        validate_pri_key('nc_scapy_pkt kep4', pri_key)
        pub_key = None
        pub_key = fields[1]

        if pub_key is not None:
            validate_pub_key('nc_scapy_pkt kep4', pub_key)
            # NOTE: not validating if it is in the curve
        else:
            pri_key_int = bytes_to_int(pri_key)
            pub_key_int = scalar_mult(pri_key_int, (EC_XG_INT, EC_YG_INT))
            pub_key = (int_to_bytes(pub_key_int[0]), int_to_bytes(pub_key_int[1]))
            validate_point('nc_scapy_pkt kep4', pub_key)

        xD = pub_key[0]
        yD = pub_key[1]
        # NOTE: preprend \x00 if coordinate starts with 0b1
        if bin(xD[0]).startswith('0b1'):
            xD = b'\x00' + xD
        if bin(yD[0]).startswith('0b1'):
            yD = b'\x00' + yD

        kep4_scapy = SCAPY_KEP4_TEMPLATE
        # NOTE: 32 depends on the SCAPY_KEP4_TEMPLATE
        delta = 32 - len(xD) + 32 - len(yD)
        kep4_scapy.len1 -= delta
        kep4_scapy.len2 -= delta
        kep4_scapy.len3 -= delta
        kep4_scapy.len4 -= delta
        kep4_scapy.xD = xD
        kep4_scapy.xD_len = len(xD)
        kep4_scapy.yD = yD
        kep4_scapy.yD_len = len(yD)
        # log.debug("nc_scapy_pkt kep4_hex: {}".format(raw(kep4_scapy).hex()))

        rv = kep4_scapy

    # NOTE: so far passing constant kdf1 and kdf2
    elif pt_type == 'kep2':
        kep4 = fields[0]
        validate_bytes('nc_scapy_pkt kep2', kep4)

        kep2_scapy = SCAPY_KEP2_TEMPLATE

        kep0 = Hash(SHA512(), backend=default_backend())
        kep0.update(kep4[4:])
        kep2_kdf2 = kep0.finalize()

        kep2_scapy.kdf2 = kep2_kdf2

        rv = kep2_scapy

    elif pt_type == 'kep3':
        pri_key = fields[0]
        validate_pri_key('nc_scapy_pkt kep3', pri_key)
        pub_key = None
        pub_key = fields[1]

        # NOTE: if fields[1] contains a pub_key
        if pub_key is not None:
            validate_pub_key('nc_scapy_pkt kep3', pub_key)
            # NOTE: not validating if it is in the curve
        else:
            pri_key_int = bytes_to_int(pri_key)
            pub_key_int = scalar_mult(pri_key_int, (EC_XG_INT, EC_YG_INT))
            pub_key = (int_to_bytes(pub_key_int[0]), int_to_bytes(pub_key_int[1]))
            validate_point('nc_scapy_pkt kep3', pub_key)

        xA = pub_key[0]
        yA = pub_key[1]
        # NOTE: preprend \x00 if coordinate starts with 0b1
        if bin(xA[0]).startswith('0b1'):
            xA = b'\x00' + xA
        if bin(yA[0]).startswith('0b1'):
            yA = b'\x00' + yA

        # NOTE: kdf field is kept constant so far
        kep3_scapy = SCAPY_KEP3_TEMPLATE
        # NOTE: 32 depends on the SCAPY_KEP3_TEMPLATE
        delta = 32 - len(xA) + 32 - len(yA)
        kep3_scapy.len1 -= delta
        kep3_scapy.len2 -= delta
        kep3_scapy.len3 -= delta
        kep3_scapy.len4 -= delta
        kep3_scapy.xA = xA
        kep3_scapy.xA_len = len(xA)
        kep3_scapy.yA = yA
        kep3_scapy.yA_len = len(yA)
        # log.debug("nc_scapy_pkt kep3_hex: {}".format(raw(kep3_scapy).hex()))

        rv = kep3_scapy

    elif pt_type == 'eka':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt eka", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt eka", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt eka", count)

        pt_scapy = SCAPY_KA_TEMPLATE
        pt_scapy.count = count
        pt = raw(pt_scapy)
        # log.debug("nc_scapy_pkt eka pt_hex: {} {}, count {}".format(pt.hex(),
        #     len(pt.hex()), count))
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        eka_scapy = SCAPY_EKA_TEMPLATE
        eka_scapy.iv = iv
        eka_scapy.ct = ct
        eka_scapy.mac = mac

        rv = eka_scapy

    elif pt_type == 'ewl':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt ewl", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt ewl", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt ewl", count)
        ip = fields[3]
        validate_ip("nc_scapy_pkt ewl", ip)

        wl_scapy = SCAPY_WL_TEMPLATE
        wl_scapy.count = count
        wl_scapy.ip = ip
        if fields[4] == None:
            # NOTE: use the tcp_port from the template
            pass
        else:
            tcp_port = fields[4]
            validate_tcp_port("nc_scapy_pkt ewl", tcp_port)
            wl_scapy.tcp_port = tcp_port
        pt = raw(wl_scapy)
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        # NOTE: similar to eka_scapy
        ewl_scapy = SCAPY_EWL_TEMPLATE
        ewl_scapy.iv = iv
        ewl_scapy.ct = ct
        ewl_scapy.mac = mac

        rv = ewl_scapy

    elif pt_type == 'eha':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt eha", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt eha", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt eha", count)
        essid = fields[3]
        validate_essid("nc_scapy_pkt eha", essid)
        password = fields[4]
        validate_password("nc_scapy_pkt eha", password)

        ha_scapy = SCAPY_HA_TEMPLATE
        ha_scapy.count = count
        ha_scapy.essid = essid
        ha_scapy.password = password
        if fields[5] == None:
            # NOTE: use the tcp_port from the template
            pass
        else:
            tcp_port = fields[5]
            validate_tcp_port("nc_scapy_pkt eha", tcp_port)
            ha_scapy.tcp_port = tcp_port
        pt = raw(ha_scapy)
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        # NOTE: similar to eka_scapy
        eha_scapy = SCAPY_EHA_TEMPLATE
        eha_scapy.iv = iv
        eha_scapy.ct = ct
        eha_scapy.mac = mac

        rv = eha_scapy

    elif pt_type == 'esh':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt esh", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt esh", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt esh", count)

        sh_scapy = SCAPY_SH_TEMPLATE
        sh_scapy.count = count
        pt = raw(sh_scapy)
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        esh_scapy = SCAPY_EKA_TEMPLATE
        esh_scapy.iv = iv
        esh_scapy.ct = ct
        esh_scapy.mac = mac

        rv = esh_scapy

    elif pt_type == 'esh2':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt esh2", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt esh2", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt esh2", count)

        sh2_scapy = SCAPY_SH2_TEMPLATE
        sh2_scapy.count = count
        pt = raw(sh2_scapy)
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        esh2_scapy = SCAPY_EKA_TEMPLATE
        esh2_scapy.iv = iv
        esh2_scapy.ct = ct
        esh2_scapy.mac = mac

        rv = esh2_scapy

    elif pt_type == 'pay':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt pay", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt pay", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt pay", count)
        pay = fields[3]
        validate_bytes("nc_scapy_pkt pay", pay)
        # pid = fields[4]
        # validate_bytes("nc_scapy_pkt pay", pid)


        # NOTE: uses Pt class
        pt_scapy = SCAPY_PT_TEMPLATE
        # NOTE: 4 depends on SCAPY_PT_TEMPLATE
        if len(pay) != 4:
            delta = 4 - len(pay)
            pt_scapy.len1 -= delta
            pt_scapy.len2 -= delta
            pt_scapy.len3 -= delta
            pt_scapy.pt_len = len(pay)
            pt_scapy.len4 -= delta
            pt_scapy.pay_len = len(pay)
        pt_scapy.pay = pay
        pt_scapy.count = count
        # log.debug("nc_scapy_pkt pt: {}".format(repr(pt_scapy)))

        pt = raw(pt_scapy)
        log.debug("nc_scapy_pkt pt_hex: {}".format(pt.hex()))
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        # NOTE: len fields should not be affected by len(Pt)
        pay_scapy = SCAPY_PAY_TEMPLATE
        pay_scapy.iv = iv
        pay_scapy.ct = ct
        pay_scapy.mac = mac

        rv = pay_scapy

    elif pt_type == 'pay2':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt pay2", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt pay2", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt pay2", count)
        pay_len = fields[3]  # this is the len of Pt (not Pt2)
        validate_int("nc_scapy_pkt pay2", pay_len)
        # pid = fields[4]
        # validate_bytes("nc_scapy_pkt pay2", pid)

        # NOTE: uses Pt2 class
        pt2_scapy = SCAPY_PT2_TEMPLATE
        if pay_len != 4:
            delta = 4 - pay_len
            pt2_scapy.pt_len = pay_len
            pt2_scapy.pt_len2 = pay_len
        pt2_scapy.count = count
        # log.debug("nc_scapy_pkt pt2: {}".format(repr(pt2_scapy)))

        pt = raw(pt2_scapy)
        log.debug("nc_scapy_pkt pt2_hex: {}".format(pt.hex()))
        # log.debug("nc_scapy_pkt pay pt_hex: {} {}, count {}".format(pt.hex(),
        #     len(pt.hex()), count))
        ct = nc_encrypt(key, pt, iv)[2]
        mac = nc_mac(key, ct, iv, pt_type)[2]

        pay2_scapy = SCAPY_PAY2_TEMPLATE
        pay2_scapy.iv = iv
        pay2_scapy.ct = ct
        pay2_scapy.mac = mac

        rv = pay2_scapy

    # NOTE: not encrypted, key and iv not used
    elif pt_type == 'iw':
        key = fields[0]
        validate_aes256_key("nc_scapy_pkt iw", key)
        iv = fields[1]
        validate_iv("nc_scapy_pkt iw", iv)
        count = fields[2]
        validate_int("nc_scapy_pkt iw", count)
        eid = eid[2]
        validate_str("nc_scapy_pkt iw", eid)

        iw_scapy = SCAPY_IW_TEMPLATE
        iw_scapy.count = count
        iw_scapy.eid = eid
        pt = raw(iw_scapy)
        # log.debug("nc_scapy_pkt iw pt_hex: {} {}, count {}".format(pt.hex(),
        #     len(pt.hex()), count))

        rv = iw_scapy

    else:
        log.error('nc_scapy_pkt: pt_type {} not managed.'.format(pt_type))

    return rv


def nc_ecdh(pri_key, x_remote, y_remote) -> bytes:
    """
        Returns the secp256r1 (NIST P-256) x[:32] of the shared secret point.

        :param pri_key: local private key int btw
        :param x_remote: x coordinate of the remote public key
        :param y_remote: y coordinate of the remote public key

        :return shared_secret: bytes

        x_remote and y_remote are in the interval [0, p]:
            [0, 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF]

        pri_key is in the interval [1, n-1]:
            [1, 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551-1]

    """

    validate_pri_key("nc_ecdh", pri_key)
    validate_point("nc_ecdh", (x_remote, y_remote))

    pri_key_int =  bytes_to_int(pri_key)
    x_remote_int = bytes_to_int(x_remote)
    y_remote_int = bytes_to_int(y_remote)
    assert is_on_curve((x_remote_int, y_remote_int))

    shared_secret_int = scalar_mult(pri_key_int, (x_remote_int, y_remote_int))
    # log.debug("nc_ecdh shared_secret_int: {}".format(shared_secret_int))

    # NOTE: take only the first 32 Bytes of the x coordinate
    shared_secret = int_to_bytes(shared_secret_int[0])[0:32]
    log.debug("nc_ecdh shared_secret: {}".format(shared_secret.hex()))
    assert len(shared_secret) == 32

    return shared_secret


def nc_kep(kep2, kep4) -> bool:
    """
    Check that sha512(kep4[4:] = Kep2.kdf2

    :param kep2: bytes, sent by the dsc
    :param kep4: bytes, sent by the dsc

    :return: bool
    """
    validate_kep2("nc_kep", kep2)
    validate_kep4("nc_kep", kep4)

    kep0 = Hash(SHA512(), backend=default_backend())
    kep0.update(kep4[4:])
    kep0_out = kep0.finalize()

    left = kep0_out
    right = Kep2(kep2).kdf2
    log.debug("nc_kep left : {}, {}".format(left.hex(), len(left.hex())))
    log.debug("nc_kep right: {}, {}".format(right.hex(), len(right.hex())))

    return left == right


def nc_kdf(shared_secret, kep2, kep3) -> list:
    """
    Return a list of results from the kdf procedure.

    :param shared_secret: bytes
    :param kep2: bytes, sent by the dsc
    :param kep3: bytes, sent by the adv

    :return: list of results

    Kep2 might be containied in a single payload together with Kep1.

    Interesting return values:

        rv[6] = cli2ser_key: dsc (encrypt) --> adv (decrypt)
        rv[8] = ser2cli_key: adv (encrypt) --> dsc (decrypt)
        rv[9] = auth token

    """
    validate_shared_secret("nc_kdf", shared_secret)
    validate_kep2("nc_kdf", kep2)
    validate_kep3("nc_kdf", kep3)

    rv = []

    kdf1 = Hash(SHA256(), backend=default_backend())
    kdf1.update(shared_secret)
    kdf1_out = kdf1.finalize()
    # log.debug("nc_kdf kdf1_out: {}, {}".format(kdf1_out, type(kdf1_out)))
    rv.append(kdf1_out)

    kdf2 = HMAC(NC_STR_UKEY2v1auth, SHA256(), backend=default_backend())
    kdf2.update(kdf1_out)
    kdf2_out = kdf2.finalize()
    # log.debug("nc_kdf kdf2_out: {}, {}".format(kdf2_out, type(kdf2_out)))
    rv.append(kdf2_out)

    kdf3 = HMAC(kdf2_out, SHA256(), backend=default_backend())
    kdf3_inp_hex  = kep2[4:].hex() + kep3[4:].hex()
    # log.debug("nc_kdf kdf3_inp_hex: {}, {}".format(kdf3_inp_hex, len(kdf3_inp_hex)))
    kdf3_inp = unhexlify(kdf3_inp_hex)
    # NOTE: heuristic
    assert len(kdf3_inp) == 252 or len(kdf3_inp) == 253 or len(kdf3_inp) == 254
    kdf3.update(kdf3_inp)
    kdf3.update(b'\x01')
    kdf3_out = kdf3.finalize()
    # log.debug("nc_kdf kdf3_out: {}, {}".format(kdf3_out, type(kdf3_out)))
    rv.append(kdf3_out)

    kdf4 = HMAC(NC_STR_UKEY2v1next, SHA256(), backend=default_backend())
    kdf4.update(kdf1_out)
    kdf4_out = kdf4.finalize()
    # log.debug("nc_kdf kdf4_out: {}, {}".format(kdf4_out, type(kdf4_out)))
    rv.append(kdf4_out)

    # NOTE: same inputs of kdf3
    kdf5 = HMAC(kdf4_out, SHA256(), backend=default_backend())
    kdf5.update(kdf3_inp)
    kdf5.update(b'\x01')
    kdf5_out = kdf5.finalize()
    # log.debug("nc_kdf kdf5_out: {}, {}".format(kdf5_out, type(kdf5_out)))
    rv.append(kdf5_out)

    kdf6 = HMAC(NC_KDF_KEY, SHA256(), backend=default_backend())
    kdf6.update(kdf5_out)
    kdf6_out = kdf6.finalize()
    # log.debug("nc_kdf kdf6_out: {}, {}".format(kdf6_out, type(kdf6_out)))
    rv.append(kdf6_out)

    # NOTE: computes cli2ser_key
    kdf7 = HMAC(kdf6_out, SHA256(), backend=default_backend())
    kdf7.update(NC_STR_CLIENT)
    kdf7.update(b'\x01')
    kdf7_out = kdf7.finalize()
    # log.debug("nc_kdf kdf7_out: {}, {}".format(kdf7_out, type(kdf7_out)))
    cli2ser_key = kdf7_out
    log.debug("nc_kdf cli2ser_key: {}, {}".format(kdf7_out, len(kdf7_out)))
    rv.append(kdf7_out)

    # NOTE: same as kdf6
    kdf8 = HMAC(NC_KDF_KEY, SHA256(), backend=default_backend())
    kdf8.update(kdf5_out)
    kdf8_out = kdf8.finalize()
    # log.debug("nc_kdf kdf8_out: {}, {}".format(kdf8_out, type(kdf8_out)))
    rv.append(kdf8_out)

    # NOTE: computes ser2cli_key
    kdf9 = HMAC(kdf8_out, SHA256(), backend=default_backend())
    kdf9.update(NC_STR_SERVER)
    kdf9.update(b'\x01')
    kdf9_out = kdf9.finalize()
    # log.debug("nc_kdf kdf9_out: {}, {}".format(kdf9_out, type(kdf9_out)))
    ser2cli_key = kdf9_out
    log.debug("nc_kdf ser2cli_key: {}, {}".format(kdf9_out, len(kdf9_out)))
    rv.append(kdf9_out)

    # NOTE: computes auth token from kdf3_out
    r_auth_token = b64encode(kdf3_out)[:5]
    auth_token = r_auth_token.decode('utf-8').upper()
    assert len(auth_token) == 5
    log.debug("nc_kdf auth_token: {}, {}".format(auth_token, len(auth_token)))
    rv.append(auth_token)

    return rv


def nc_encrypt(key, pt, iv) -> list:
    """

    :param key: either cli2ser_key or ser2cli_key
    :param pt: bytes
    :param iv: bytes

    :return: list

    Return values:

        rv[1] = derived key
        rv[2] = ct
    """

    validate_aes256_key("nc_encrypt", key)
    validate_pt("nc_encrypt", pt)
    validate_iv("nc_encrypt", iv)

    rv = []

    # NOTE: same block used for decryption
    enc1 = HMAC(NC_KEY, SHA256(), backend=default_backend())
    enc1.update(key)
    enc1_out = enc1.finalize()
    # log.debug("nc_encrypt enc1_out: {}, {}".format(enc1_out, type(enc1_out)))
    rv.append(enc1_out)
    enc2 = HMAC(enc1_out, SHA256(), backend=default_backend())
    enc2.update(NC_STR_ENC2)
    enc2.update(b'\x01')
    enc2_out = enc2.finalize()
    # log.debug("nc_encrypt enc2_out: {}, {}".format(enc2_out, type(enc2_out)))
    # log.debug("nc_encrypt enc2_out is the symmetric key: {}".format(enc2_out))
    rv.append(enc2_out)
    mode = CBC(iv)
    cipher = Cipher(AES(enc2_out), mode, backend=default_backend())

    # NOTE: encryptor does not pad automatically
    encryptor = cipher.encryptor()
    if (len(pt) % AES_BLOCK_BYTES != 0):
        padder = PKCS7(AES_BLOCK_BITS).padder()
        pt_p = padder.update(pt) + padder.finalize()
    else:
        pt_p = pt
    # log.debug("nc_encrypt: pt_p {}, {}, {}".format(pt_p, len(pt_p), type(pt_p)))
    ct = encryptor.update(pt_p) + encryptor.finalize()
    # log.debug("nc_encrypt ct {}, {}, {}".format(ct, len(ct), type(ct)))
    rv.append(ct)

    return rv


def nc_decrypt(key, ct, iv) -> list:
    """

    :param key: either cli2ser_key or ser2cli_key
    :param ct: bytes
    :param iv: bytes

    :return: list

    Return values:

        rv[1] = derived key
        rv[2] = pt
    """

    validate_aes256_key("nc_decrypt", key)
    validate_ct("nc_decrypt", ct)
    validate_iv("nc_decrypt", iv)

    rv = []

    # NOTE: same block used for encryption
    dec1 = HMAC(NC_KEY, SHA256(), backend=default_backend())
    dec1.update(key)
    dec1_out = dec1.finalize()
    # log.debug("nc_decrypt dec1_out: {}, {}".format(dec1_out, type(dec1_out)))
    rv.append(dec1_out)
    dec2 = HMAC(dec1_out, SHA256(), backend=default_backend())
    dec2.update(NC_STR_ENC2)
    dec2.update(b'\x01')
    dec2_out = dec2.finalize()
    # log.debug("nc_decrypt dec2_out: {}, {}".format(dec2_out, type(dec2_out)))
    # log.debug("nc_decrypt dec2_out is the symmetric key: {}".format(dec2_out))
    rv.append(dec2_out)
    mode = CBC(iv)
    cipher = Cipher(AES(dec2_out), mode, backend=default_backend())

    # NOTE: decryptor does not unpad automatically
    decryptor = cipher.decryptor()
    pt_p = decryptor.update(ct) + decryptor.finalize()
    # log.debug("nc_decrypt: pt_p: {}, {}. {}".format(pt_p, len(pt_p), type(pt_p)))
    # if (len(pt_p) % AES_BLOCK_BYTES != 0):
    #     unpadder = PKCS7(AES_BLOCK_BITS).unpadder()
    #     pt = unpadder.update(pt_p) + unpadder.finalize()
    # else:
    #     pt = pt_p
    unpadder = PKCS7(AES_BLOCK_BITS).unpadder()
    pt = unpadder.update(pt_p) + unpadder.finalize()
    # log.debug("nc_decrypt: pt: {}, {}. {}".format(pt, len(pt), type(pt)))
    rv.append(pt)

    return rv


def nc_mac(key, ct, iv, pt_type) -> list:
    """NC AES encryption key computation

    :param key: either cli2ser_key or ser2cli_key
    :param ct: bytes
    :param iv: bytes
    :param pt_type: string in PT_TYPES

    :return: list

    Return values:

        rv[2] = mac
    """

    validate_aes256_key("nc_mac", key)
    validate_ct("nc_mac", ct)
    validate_iv("nc_mac", iv)
    validate_pt_type("nc_mac", pt_type)

    rv = []

    mac1 = HMAC(NC_KEY, SHA256(), backend=default_backend())
    mac1.update(key)
    mac1_out = mac1.finalize()
    # log.debug("nc_mac mac1_out: {}, {}".format(mac1_out, type(mac1_out)))
    rv.append(mac1_out)

    mac2 = HMAC(mac1_out, SHA256(), backend=default_backend())
    mac2.update(NC_STR_SIG1)
    mac2.update(b'\x01')
    mac2_out =mac2.finalize()
    # log.debug("nc_mac mac2_out: {}, {}".format(mac2_out, type(mac2_out)))
    rv.append(mac2_out)

    # NOTE: conditional to the type of ct (and indeed pt)
    mac3 = HMAC(mac2_out, SHA256(), backend=default_backend())
    mac3_inp_hex = NC_MAC_PRE_IV + iv.hex() + NC_MAC_POST_IV[pt_type] + ct.hex()
    mac3_inp = unhexlify(mac3_inp_hex)
    mac3.update(mac3_inp)
    mac3_out =mac3.finalize()
    # log.debug("nc_mac mac3_out: {}, {}".format(mac3_out, type(mac3_out)))
    rv.append(mac3_out)

    return rv


