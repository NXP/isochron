#!/usr/bin/python3

from statistics import mean, stdev
import sys
import re

NSEC_PER_SEC = 1000000000

def timespec_to_ns(ts):
    words = ts.split('.')

    if len(words) == 1:
        sec = 0
        nsec = int(words[0])
    elif len(words) == 2:
        sec = int(words[0])
        while len(words[1]) < 9:
            words[1] += '0'
        nsec = int(words[1])
    else:
        print('Invalid time {}'.format(ts))
        exit(1)

    return (sec * NSEC_PER_SEC) + nsec

def ns_to_timespec(ns, relative=False):
    prefix = ''

    ns = int(ns)
    if (ns < 0):
        prefix = '-'
        ns = -ns
    elif relative:
        prefix = '+'

    sec = int(ns / NSEC_PER_SEC)
    nsec = ns % NSEC_PER_SEC
    return '{}{}.{:09d}'.format(prefix, sec, nsec)

def utc_to_tai(ns):
    return ns + utc_offset

def usage():
    print("Usage: " + sys.argv[0] +
          "raw-l2-send-output.txt " +
          "raw-l2-rcv-output.txt " +
          "utc-offset " +
          "advance-time")
    exit(1)

if (len(sys.argv) != 5):
    usage()

class tstamp_set():
    def __init__(self, seqid, app, driver, scheduled, mac):
        self.seqid = seqid
        self.app = app
        self.driver = driver
        self.scheduled = scheduled
        self.mac = mac

def parse(raw_l2_send_txt, raw_l2_rcv_txt):
    with open(raw_l2_send_txt, 'r') as raw_l2_send:
        tx_log = raw_l2_send.readlines()

    with open(raw_l2_rcv_txt) as raw_l2_rcv:
        rx_log = raw_l2_rcv.readlines()

    for tx_line in tx_log:
        tx_words = tx_line.split()
        if (len(tx_words) < 11):
            # Skip malformed lines
            continue
        tx_seqid = int(tx_words[8])

        found = False

        for rx_line in rx_log:
            rx_words = rx_line.split()
            # Skip malformed lines
            if (len(rx_words) < 9):
                continue
            rx_seqid = int(rx_words[8])
            if (tx_seqid == rx_seqid):
                found = True
                break

        if not found:
            print("seqid {} lost".format(tx_seqid))
            continue

        m = re.search('\[(.*)\]', tx_words[0])
        if not m:
            print("Malformed TX time {}".format(tx_words[0]))
            continue
        tx_app_swtstamp = timespec_to_ns(m.group(1))
        tx_scheduled_time = timespec_to_ns(tx_words[5])
        tx_mac_hwtstamp = timespec_to_ns(tx_words[10])
        tx_driver_swtstamp = timespec_to_ns(tx_words[12])

        m = re.search('\[(.*)\]', rx_words[0])
        if not m:
            print("Malformed RX time {}".format(rx_words[0]))
            continue
        rx_app_swtstamp = timespec_to_ns(m.group(1))
        rx_mac_hwtstamp = timespec_to_ns(rx_words[10])
        rx_driver_swtstamp = timespec_to_ns(rx_words[12])

        tx = tstamp_set(seqid=tx_seqid,
                        app=utc_to_tai(tx_app_swtstamp),
                        driver=utc_to_tai(tx_driver_swtstamp),
                        scheduled=utc_to_tai(tx_scheduled_time),
                        mac=tx_mac_hwtstamp)
        rx = tstamp_set(seqid=rx_seqid,
                        app=utc_to_tai(rx_app_swtstamp),
                        driver=utc_to_tai(rx_driver_swtstamp),
                        scheduled=utc_to_tai(tx_scheduled_time), # Unused
                        mac=rx_mac_hwtstamp)
        process(tx, rx)

def process(tx, rx):
    tx_app_wakeup = tx.scheduled - advance_time

    gate_time.append(tx.scheduled)
    tx_app_latency.append(tx.app - tx_app_wakeup)
    tx_driver_latency.append(tx.driver - tx.app)
    tx_mac_latency.append(tx.mac - tx.driver)
    tx_mac_gate_accuracy.append(tx.mac - tx.scheduled)
    path_delay.append(rx.mac - tx.mac)
    rx_driver_latency.append(rx.driver - rx.mac)
    rx_app_latency.append(rx.app - rx.driver)

    print(('seqid {} Gate {} TX app {} TX driver {} ' +
           'TX MAC {} Path {} RX driver {} ' +
           'RX app {}').format(tx.seqid,
            ns_to_timespec(gate_time[-1]),
            ns_to_timespec(tx_app_latency[-1]),
            ns_to_timespec(tx_driver_latency[-1]),
            ns_to_timespec(tx_mac_latency[-1]),
            ns_to_timespec(path_delay[-1]),
            ns_to_timespec(rx_driver_latency[-1]),
            ns_to_timespec(rx_app_latency[-1])))

def print_array(label, array):
    print('{} (ns): max {} min {} mean {} stddev {}'.format(label,
          ns_to_timespec(min(tx_app_latency)),
          ns_to_timespec(max(tx_app_latency)),
          ns_to_timespec(mean(tx_app_latency)),
          ns_to_timespec(stdev(tx_app_latency))))

def results():
    print_array('TX app latency', tx_app_latency)
    print_array('TX driver latency', tx_driver_latency)
    print_array('TX MAC latency', tx_mac_latency)
    print_array('TX MAC gate accuracy', tx_mac_gate_accuracy)
    print_array('Path delay', path_delay)
    print_array('RX driver latency', rx_driver_latency)
    print_array('RX app latency', rx_app_latency)

utc_offset = timespec_to_ns(sys.argv[3])
advance_time = timespec_to_ns(sys.argv[4])
gate_time = []
tx_app_latency = []
tx_driver_latency = []
tx_mac_latency = []
tx_mac_gate_accuracy = []
path_delay = []
rx_driver_latency = []
rx_app_latency = []

parse(sys.argv[1], sys.argv[2])
results()
