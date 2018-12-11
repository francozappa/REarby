# README

**2018-09-14: Please do not to distribute it to anyone not involved with the disclosure process.**

* Deps
    * `python3`
    * `scapy`
    * `create_ap` or similar tools
        * https://github.com/oblique/create_ap
    * `wireshark` or `tcpdump`

Steps to reproduce the attack:

* Attacker running Linux
    * Make sure that `bluetoothd` runs with `-C`
    * Set you Bluetooth adapter to discoverable
    * Disconnect from any wireless network
    * `sudo create_ap -w 1 -c 9 wlp4s0 enp0s25 B6RX1qnuNtFwxi4d5_U6F41ASmME AzrQq1KyjRnW`
    * If the AP address is not `192.168.12.1` change line 60 in `attack.py` script with the correct IP address
    * optionally wireshark on `bluetooth0` and filter for RFCOMM traffic 
      eg: `btrfcomm` display filter
    * optionally wireshark on `ap0` to see the WLAN traffic
    * Rename your Bluetooth adapter to `ITR1ZEE0s2QAAAAAAAAABG5hbWU`
        * This name depends on several application layer parameters
        * If you change any of them eg: `sid` then the name and other values 
          have to be changed accordingly
    * `sudo python3 attack.py`

* Victim is a Nexus5 (we also tested it on other devices)
    * Install `nexus5-rps.apk`
        * `adb install -t nexus5-rps.apk`
    * Switch off WiFi antenna using the Android software switch
    * Start the RockPaperScissors app
    * Set strategy to `P2P_STAR` by clicking the S Bt+Wifi button
    * Start discovering by clicking DSC ON
    * Accept the connection from the malicious advertiser

After some time the victim will switch on its wifi antenna and connect to the
AP controlled by the attacker. The essid is `B6RX1qnuNtFwxi4d5_U6F41ASmME`
You can confirm it by looking at the wireshark capture from your AP and by
seeing that in the victim phone the apps that are using the WiFi in background
continue to work eg: update to apps, push notifications, etc




