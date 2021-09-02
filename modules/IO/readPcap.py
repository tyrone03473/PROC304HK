# -*- coding: utf-8 -*-

def read_pcap(filepath: str) -> bytes:
    fpcap = open(filepath, 'rb')
    string_data = fpcap.read()
    fpcap.close()
    return string_data


# def read_text(filepath: str) -> str:
#     fpcap = open(filepath, 'r')
#     string_data = fpcap.read()
#     fpcap.close()
#
#     # test
#     # print(string_data[:20])
#
#     return string_data


if __name__ == '__main__':
    string_ = read_pcap("../../test/test.pcap")
    print(string_)
