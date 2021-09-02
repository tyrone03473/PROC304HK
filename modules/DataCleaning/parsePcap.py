# -*- coding: utf-8 -*-
from modules.IO.readPcap import read_pcap
from modules.DataCleaning.decodeHTTP import *

import struct


# test
def print_Dict(dic: dict) -> None:
    if len(dic) < 1:
        print("The Dic is empty!")
        return None
    for key in dic:
        print(key, ":", dic[key])
    return None


def get_global_header(bytespcap: bytes) -> dict:
    # bytespcap is the content of the entire pcap file. The type is bytes
    print("Size of PCAP file：", len(bytespcap))
    bytes_global_header = bytespcap[:24]

    # The length of pcap header is 24 bytes
    # print("PCAP header information：", bytes_global_header)

    dict_global_header = {}
    dict_global_header['magic_number'] = bytes_global_header[:4]
    dict_global_header['version_major'] = bytes_global_header[4:6]
    dict_global_header['version_minor'] = bytes_global_header[6:8]
    dict_global_header['thiszone'] = bytes_global_header[8:12]
    dict_global_header['sigfigs'] = bytes_global_header[12:16]
    dict_global_header['snaplen'] = bytes_global_header[16:20]
    dict_global_header['linktype'] = bytes_global_header[20:]

    print("- " * 30, "\n##PCAP Global Header\n", "- " * 30,)
    print_Dict(dict_global_header)
    print("- " * 30)
    return dict_global_header


def get_packet_header(bytes_packet_header: bytes) -> dict:
    # bytes_packet_Header is 16 bytes
    # Pcap header length 16 bytes
    print("packet header:", bytes_packet_header)

    dict_packet_header = {}
    dict_packet_header['GMTtime'] = bytes_packet_header[:4]
    dict_packet_header['MicroTime'] = bytes_packet_header[4:8]
    dict_packet_header['caplen'] = bytes_packet_header[8:12]
    dict_packet_header['len'] = bytes_packet_header[12:16]

    # test
    print_Dict(dict_packet_header)
    return dict_packet_header


def deal_packet_data(packetdata: str) -> None:
    # ether = dpkt.ethernet.Ethernet(packetdata)
    try:
        decodePacket(packetdata)
    except Exception as e:
        print('something wrong in data, error:{}'.format(e))


def get_packet_data(bytespcap: bytes, start: str, stop: str) -> bytes:
    # start: keylen
    # stop: len_packet_data
    packet_data = bytespcap[start + 16:start + 16 + stop]
    print("len ==>", stop, "bytes")
    # print("Packet content:", packet_data)
    deal_packet_data(packet_data)
    return packet_data


def get_packet(bytespcap: bytes) -> None:
    # Bytes pcap is the bytes of the entire pcap file
    # The first 24 bytes are global_header
    keylen = 24
    packet_num = 0

    print("##PCAP packet")
    print('- '*30)
    while keylen < len(bytespcap):
        packet_num += 1
        print("packet num:", packet_num)
        dict_packet_header = get_packet_header(bytespcap[keylen:keylen+16])
        len_packet_data = struct.unpack('I', dict_packet_header['len'])[0]
        packet_data = get_packet_data(bytespcap, keylen, len_packet_data)

        # print("Packet content:", packet_data)
        keylen = keylen + 16 + len_packet_data
        print("- "*30)

    print("Parsing complete!")
    return None


def parsePcap(Path: str) -> None:
    string_bytes = read_pcap(Path)
    get_global_header(string_bytes)
    get_packet(string_bytes)


if __name__ == '__main__':
    parsePcap("../../test/test2.pcap")






