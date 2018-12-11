"""
pub_api.py

"""

from lib import *
log.setLevel(logging.DEBUG)

NC_PT_TYPES = [
    # NOTE: encrypted
    'eka',
    'ewd',
    'eha',
    'esh', 'esh2',
    'ewl',
    'pay', 'pay2',
    # NOTE: not encrypted
    'kep1', 'kep2', 'kep3', 'kep4',
    'iw',
]



class RemoteAdvertiser:

    """
    Used to store data about the remote node
    """

    _version = '1.0.0'

    def __init__(self, strategy, sid):

        self.strategy = strategy
        self.sid = sid

        self.btaddr = None
        self.btname = None
        self.eid = None
        self.ncname = None
        self.uuid = None
        self.sock = None
        self.ip = None
        self.tcp_port = None
        self.essid = None
        self.password = None


class RemoteDiscoverer:

    """
    Used to store data about the remote node
    """

    _version = '1.0.0'

    def __init__(self, strategy, sid):

        self.strategy = strategy
        self.sid = sid

        self.btaddr = None
        self.btname = None
        self.eid = None
        self.ncname = None
        self.sock = None
        self.ip = None
        self.tcp_port = None


class Advertiser:

    """
    Advertiser
    """

    _version = '1.0.0'

    def __init__(self, strategy, sid, ncname, eid, wifi_mode, port=5):

        self.strategy = strategy
        self.sid = sid
        self.ncname = ncname
        self.eid = eid
        self.wifi_mode = wifi_mode
        self.port = port

        self.server_sock = None
        self.rdsc = RemoteDiscoverer(self.strategy, self.sid)
        assert self.strategy == self.rdsc.strategy
        assert self.sid == self.rdsc.sid

        self.kep1 = None
        self.kep2 = None
        self.kep3 = None
        self.kep4 = None
        self.r_kep1 = None
        self.r_kep2 = None
        self.r_kep3 = None
        self.r_kep4 = None

        # self.pri_key = int_to_bytes(randint(2, 3000))
        # self.pri_key = b'\x02'
        self.pri_key = urandom(4)
        self.pub_key = None
        self.shared_secret = None
        self.dsc2adv_key = None
        self.adv2dsc_key = None
        self.auth_token  = None

        self.d2a_count = 0
        self.a2d_count = 0

        self._compute_btname()
        self._precompute_kep()

    def _compute_btname(self):
        """Compute btname according to strategy, eid, ncname and sid."""

        # btname = get_adv_btname(P2P_CLUSTER, eid, ncname, sid)
        if self.strategy == 'P2P_STAR':
            self.btname = get_adv_btname('!', self.eid, self.ncname, self.sid)
        elif self.strategy == 'P2P_CLUSTER':
            self.btname = get_adv_btname('"', self.eid, self.ncname, self.sid)
        log.debug("Adv btname: {}".format(self.btname))

    def _precompute_kep(self):
        """Pre compute Kep3

        r_* packets are created from scapy ones and sent.
        """

        self.kep3 = nc_scapy_pkt('kep3', [self.pri_key, self.pub_key])
        log.debug("Adv pri_key: {}".format(self.pri_key))
        self.r_kep3 = raw(self.kep3)

    def advertise(self, max_con=1, prompt=False):
        """Start RFCOMM and SDP servers"""

        if prompt:
            _ = input("Adv bluetoothd -C, {}, {}, {}, {}, {}, {}, start wireshark.".format(
                self.strategy, self.sid, self.eid, self.ncname, self.btname, self.wifi_mode))

        self.server_sock = BluetoothSocket(RFCOMM)
        self.server_sock.bind(("", self.port))
        self.server_sock.listen(max_con)
        log.info("Adv on port {} and accepts {}".format(self.port, max_con))
        # NOTE: uuid depends only on sid
        # uuid = sid_to_uuid(sid)
        self.uuid = "b8c1a306-9167-347e-b503-f0daba6c5723"
        # NOTE: requires bluetoothd -C
        advertise_service(
            sock=self.server_sock,
            name=self.sid,
            service_id = "",
            service_classes = [self.uuid],
        )

    def connect(self, auto_accept=True):
        """Accept BT connection, kep, kdf and AL pre-connection."""

        # NOTE: blocking
        self.rdsc.sock, info = self.server_sock.accept()
        self.rdsc.btaddr = info[0]
        log.info("Adv connected with: {}".format(self.rdsc.btaddr))

        self._do_kep()
        self._do_kdf()
        self._do_pre_connection(auto_accept)

    def _do_kep(self):
        """Do the key exchange protocol with the dsc.

        Recv kep1, kep2, kep4
        """
        data = self.rdsc.sock.recv(1024)
        # NOTE: packet contains only Kep1
        if data.find(b'AES_256_CBC-HMAC_SHA256') == -1:
            self.kep1 = Kep1(data)
            log.info("Adv rcvd Kep1")
            data = self.rdsc.sock.recv(1024)
            self.kep2 = Kep2(data)
            log.info("Adv rcvd Kep2")
        # NOTE: packet contains Kep1 and Kep2
        else:
            # NOTE: assuming that kep2 is always 140 Bytes
            self.kep1 = Kep1(data[:len(data)-NC_KEP2_LEN])
            log.info("Adv rcvd Kep1")
            self.kep2 = Kep2(data[-NC_KEP2_LEN:])
            log.info("Adv rcvd Kep2")
        self.rdsc.ncname = self.kep1.ncname
        self.rdsc.eid = self.kep1.eid
        log.debug("Adv ncname_remote: {} eid_remote:{}".format(
                    self.rdsc.ncname, self.rdsc.eid))
        # log.warning("Adv kep1.str1: {}, {}".format(kep1.str1, b64e(kep1.str1)))
        self.rdsc.kdf1 = self.kep2.kdf1
        self.r_kep2 = raw(self.kep2)
        # NOTE: Kep3
        log.debug("Adv kep3.xA: {}, {}".format(self.kep3.xA.hex(),
            len(self.kep3.xA.hex())))
        log.debug("Adv kep3.yA: {}, {}".format(self.kep3.yA.hex(),
            len(self.kep3.yA.hex())))
        self.rdsc.sock.send(self.r_kep3)
        log.info("Adv sent (precomputed) Kep3:")
        data = self.rdsc.sock.recv(1024)
        log.info("Adv rcvd Kep4:")
        # NOTE: Kep4
        self.r_kep4 = data
        self.kep4 = Kep4(data)
        log.debug("Adv kep4.xD: {}, {}".format(self.kep4.xD.hex(),
            len(self.kep4.xD.hex())))
        log.debug("Adv kep4.yD: {}, {}".format(self.kep4.yD.hex(),
            len(self.kep4.yD.hex())))
        # NOTE: commitment test done only by the adv
        if not nc_kep(self.r_kep2, self.r_kep4):
            log.error("Adv failed nc_kep check")
            exit("Adv failed nc_kep check")

    def _do_kdf(self):
        """Derives shared shared_secret, session keys and auth token."""

        self.shared_secret = nc_ecdh(self.pri_key, self.kep4.xD, self.kep4.yD)
        rv = nc_kdf(self.shared_secret, self.r_kep2, self.r_kep3)
        self.dsc2adv_key = rv[6]
        self.adv2dsc_key = rv[8]
        self.auth_token  = rv[9]
        log.debug("Adv ss: {} token: {}".format(self.shared_secret, self.auth_token))

    def _do_pre_connection(self, auto_accept):
        """Do the pre-connection phase."""

        while True:
            data = self.rdsc.sock.recv(1024)
            if data.find(NC_KA_PRE_CON) != -1:
                log.info("Adv recv a preconn ka.")
                self.rdsc.sock.send(NC_KA_PRE_CON)
                log.debug("Adv sent a preconn ka.")
            elif data.find(NC_ACCEPT_CON) != -1:
                log.info("Dsc accepted the connection.")
                if auto_accept:
                    self.rdsc.sock.send(NC_ACCEPT_CON)
                    log.debug("Adv accepted the connection.")
                else:
                    log.debug("Adv still has to accept the connection.")
                break
            elif data.find(NC_REJECT_CON) != -1:
                log.info("Dsc rejected the connection.")
                self.rdsc.sock.send(NC_REJECT_CON)
                log.debug("Adv rejected the connection.")
                exit("Adv and Dsc rejected the connection.")
            else:
                log.warning("Adv don't know how to handle  {}.".format(data))

    def send(self, ptype, pargs=None, eid=None, blocking=True ):
        """Send a NCPacket of ptype to eid and returns it.

        pargs contains parameters to be used by nc_scapy_pkt
        """

        if eid is None:
            eid = self.rdsc.eid
        iv = urandom(AES_IV_BYTES)
        self.a2d_count += 1
        if pargs is None:
            pkt = NCPacket(ptype, self.adv2dsc_key, iv, self.a2d_count)
        else:
            pkt = NCPacket(ptype, self.adv2dsc_key, iv, self.a2d_count, *pargs)
        log.debug("Adv send: {}, a2d_count: {}".format(pkt.ptype,
            self.a2d_count))
        self.rdsc.sock.send(raw(pkt.scapy))
        return pkt

    def recv(self, eid=None, blocking=True):
        """Recv and returns a NCPacket from eid."""

        if eid is None:
            eid = self.rdsc.eid
        self.d2a_count += 1
        data = self.rdsc.sock.recv(1024)
        pkt = NCPacket(data, self.dsc2adv_key, None, self.d2a_count)
        log.debug("Adv rcvd ka: {}, d2a_count: {}".format(pkt.pt, pkt.pt.count))
        return pkt

    def disconnect(self):
        """disconnect"""
        if self.rdsc.sock is None:
            log.info("Adv: no client socket to disconnect from")
        else:
            self.rdsc.sock.close()
            self.rdsc.sock = None
        if self.server_sock is None:
            log.info("Adv: no server socket to disconnect from")
        else:
            self.server_sock.close()
            self.server_sock = None

    def __repr__(self):
        return 'Adv:' + repr((self.strategy, self.sid, self.eid, self.ncname))

    def __str__(self):
        return 'Adv:' + repr((self.strategy, self.sid, self.eid, self.ncname))


class Discoverer:

    """
    Discoverer
    """

    _version = '1.0.0'

    def __init__(self, btaddr, btname, strategy, sid, ncname, eid, wifi_mode='hostapd'):

        self.btaddr = btaddr
        self.btname = btname
        self.strategy = strategy
        self.sid = sid
        self.ncname = ncname
        self.eid = eid
        self.wifi_mode = wifi_mode

        self.port = None  # 5, 10
        self.advs = None
        self.radv = RemoteAdvertiser(self.strategy, self.sid)
        assert self.strategy == self.radv.strategy
        assert self.sid == self.radv.sid

        self.kep1 = None
        self.kep2 = None
        self.kep3 = None
        self.kep4 = None
        self.r_kep1 = None
        self.r_kep2 = None
        self.r_kep3 = None
        self.r_kep4 = None

        # self.pri_key = int_to_bytes(randint(2, 3000))
        # self.pri_key = b'\x02'
        self.pri_key = urandom(4)
        self.pub_key = None
        self.shared_secret = None
        self.dsc2adv_key = None
        self.adv2dsc_key = None
        self.auth_token  = None

        self.d2a_count = 0
        self.a2d_count = 0

        self._precompute_kep()

    def _precompute_kep(self):
        """Pre compute Kep1, Kep4 and Kep2.

        Kep4 before Kep2 because of sha512

        r_* packets are created from scapy ones and sent.
        """

        self.kep1 = nc_scapy_pkt('kep1', [self.eid, self.ncname,
            self.strategy, self.wifi_mode])
        self.r_kep1 = raw(self.kep1)
        log.debug("Dsc r_kep1: {}".format(self.r_kep1))
        self.kep4 = nc_scapy_pkt('kep4', [self.pri_key, self.pub_key])
        log.debug("Dsc pri_key: {}".format(self.pri_key))
        log.debug("Dsc pub_key: {}".format(self.pub_key))
        self.r_kep4 = raw(self.kep4)
        log.debug("Dsc r_kep4: {}".format(self.r_kep4))
        self.kep2 = nc_scapy_pkt('kep2', [self.r_kep4])
        self.r_kep2 = raw(self.kep2)
        log.debug("Dsc r_kep2: {}".format(self.r_kep2))

    def discover(self, duration):

        advs, others = discover_bt(duration)
        if not advs:
            exit("Dsc no devices discovered")
        else:
            self.advs = advs
            log.info("Dsc discovered: {}".format(advs))

    def connect(self, btaddr, btname, auto_accept=True):
        """Connect to an advertiser

        If auto_accept is False you have to manually accept the connection."""

        self.radv.btaddr = btaddr
        self.radv.btname = btname
        _, self.radv.eid, _, self.radv.ncname = get_adv_parameters(self.radv.btname)
        self.radv.uuid = sid_to_uuid(self.sid)
        # XXX strengthen
        log.warning('Dsc uuid is hardcoded')
        self.radv.uuid = "b8c1a306-9167-347e-b503-f0daba6c5723"
        sdps = find_service(address=self.radv.btaddr, uuid=self.radv.uuid)
        if not sdps:
            exit("Dsc no sdp with uuid: {}".format(self.radv.uuid))
        self.radv.sdp = sdps[0]
        log.info("Dsc found sdp_nc: {}".format(self.radv.sdp))
        assert self.radv.sdp["host"] == self.radv.btaddr
        assert self.radv.sdp["name"] == self.radv.sid
        self.port = self.radv.sdp["port"]
        try:
            self.radv.sock = BluetoothSocket(RFCOMM)
            self.radv.sock.connect((self.radv.btaddr, self.port))
            log.info("Dsc connecting to: {} port: {}".format(self.radv.btaddr,
                self.port))
            self._do_kep()
            self._do_kdf()
            self._do_pre_connection(auto_accept)

        except IOError:
            pass
        except Exception as e:
            raise e

    def _do_kep(self):
        """Do the key exchange protocol with the adv.

        Recv kep3
        """

        self.radv.sock.send(self.r_kep1)
        log.info("Dsc sent (precomputed) Kep1:")
        self.radv.sock.send(self.r_kep2)
        log.info("Dsc sent(precomputed) Kep2:")
        data = self.radv.sock.recv(1024)
        log.info("Dsc rcvd Kep3: {}".format(data.hex()))
        self.r_kep3 = data
        self.kep3 = Kep3(data)
        log.debug("Dsc kep3.xA: {}, {}".format(self.kep3.xA.hex(),
            len(self.kep3.xA.hex())))
        log.debug("Dsc kep3.yA: {}, {}".format(self.kep3.yA.hex(),
            len(self.kep3.yA.hex())))
        self.radv.sock.send(self.r_kep4)
        log.info("Dsc sent(precomputed) Kep4:")
        log.debug("Dsc kep4.xD: {}, {}".format(self.kep4.xD.hex(),
            len(self.kep4.xD.hex())))
        log.debug("Dsc kep4.yD: {}, {}".format(self.kep4.yD.hex(),
            len(self.kep4.yD.hex())))
        # NOTE: commitment test done only by the adv
        if not nc_kep(self.r_kep2, self.r_kep4):
            log.error("Dsc failed nc_kep check")
            exit("Dsc failed nc_kep check")

    def _do_kdf(self):
        """Derives shared shared_secret, session keys and auth token."""

        self.shared_secret = nc_ecdh(self.pri_key, self.kep3.xA, self.kep3.yA)
        rv = nc_kdf(self.shared_secret, self.r_kep2, self.r_kep3)
        self.dsc2adv_key = rv[6]
        self.adv2dsc_key = rv[8]
        self.auth_token  = rv[9]

    def _do_pre_connection(self, auto_accept):
        """Do the pre-connection phase."""

        while True:
            data = self.radv.sock.recv(1024)
            if data.find(NC_KA_PRE_CON) != -1:
                log.info("Adv sent a preconn ka.")
                self.radv.sock.send(NC_KA_PRE_CON)
                log.debug("Dsc sent a preconn ka.")
            elif data.find(NC_ACCEPT_CON) != -1:
                log.info("Adv accepted the connection.")
                if auto_accept:
                    self.radv.sock.send(NC_ACCEPT_CON)
                    log.debug("Dsc accepted the connection.")
                else:
                    log.debug("Dsc still has to accept the connection.")
                break
            elif data.find(NC_REJECT_CON) != -1:
                log.info("Adv rejected the connection.")
                self.radv.sock.send(NC_REJECT_CON)
                log.debug("Dsc rejected the connection.")
                exit("Dsc rejected the connection.")
            else:
                log.warning("Adv sent {}.".format(data))
                log.warning("Dsc don't know how to handle packet")

    def disconnect(self):

        if self.radv.sock is None:
            log.info("Dsc: no socket to disconnect from")
        else:
            self.radv.sock.close()
            self.radv.sock = None

    def __repr__(self):
        return 'Dsc:' + repr((self.strategy, self.sid, self.eid, self.ncname))

    def __str__(self):
        return 'Dsc:' + repr((self.strategy, self.sid, self.eid, self.ncname))


class NCPacket:

    """
    NCPacket

        self.scapy contains the dissected pkt using nc.py:
            self.scapy.ct contains the dissected pkt using nc.py
            self.scapy.mac contains the dissected pkt using nc.py
            self.scapy.iv contains the dissected pkt using nc.py

        To send use raw(self.scapy)

        self.pt contains the dissected pkt using nc.py:
            self.pt.essid
            self.pt.tcp_port
            self.pt.count

    """

    _version = '1.0.0'

    def __init__(self, data, *args):
        """*Returns a scapy packet

        data: either ptype or binary

        args follows the nc_scapy_pkt API:
            args[0] key, bytes
            args[1] iv, bytes
            args[2] count, int
            args[3] depdens on the ptype


        """

        # NOTE: called by send
        if type(data) == str:
            self.ptype = data
            if self.ptype not in NC_PT_TYPES:
                log.error('NCPacket __init__: ptype {} not handled'.format(ptype))
            else:
                self.scapy = nc_scapy_pkt(self.ptype, args)

        # NOTE: called by recv
        elif type(data) == bytes:
            self.raw = data
            if len(data) == NC_EKA_LEN:
                self.ptype = 'eka'
                self.scapy = Eka(data)
                mac_c = nc_mac(args[0], self.scapy.ct, self.scapy.iv, self.ptype)[2]
                assert mac_c == self.scapy.mac
                self.pt = KA(nc_decrypt(args[0], self.scapy.ct, self.scapy.iv)[2])
                assert args[2] == self.pt.count
            else:
                log.error('NCPacket __init__: type(data) {} not handled'.format(
                    type(data)))
        else:
            log.error('NCPacket __init__: data {} not handled'.format(data))





