# -*- coding: utf-8 -*-
import dpkt
import socket
import ctypes
from modules.IO.writeText import write_text, write_text_clean


'''
Use the third-party library dpkt to obtain the source IP and destination IP
'''


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_short),
                ("__pad1", ctypes.c_ushort),
                ("ipv4_addr", ctypes.c_byte * 4),
                ("ipv6_addr", ctypes.c_byte * 16),
                ("__pad2", ctypes.c_ulong)]


def followRule(ctypes):
    # Function hasattr is used to determine whether an object contains corresponding attributes
    if hasattr(ctypes, 'windll'):
        # Using ctypes module to call windows DLL file
        WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
        WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA
    else:
        def not_windows():
            raise SystemError(
                "Invalid platform. ctypes.windll must be available."
            )
        WSAStringToAddressA = not_windows
        WSAAddressToStringA = not_windows
    return WSAStringToAddressA, WSAAddressToStringA


WSAStringToAddressA, WSAAddressToStringA = followRule(ctypes)


# Standard library functions
def inet_pton(address_family, ip_string):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))

    if WSAStringToAddressA(
            ip_string,
            address_family,
            None,
            ctypes.byref(addr),
            ctypes.byref(addr_size)
    ) != 0:
        raise socket.error(ctypes.FormatError())

    if address_family == socket.AF_INET:
        return ctypes.string_at(addr.ipv4_addr, 4)
    if address_family == socket.AF_INET6:
        return ctypes.string_at(addr.ipv6_addr, 16)

    raise socket.error('unknown address family')


# Standard library functions
def inet_ntop(address_family, packed_ip):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))
    ip_string = ctypes.create_string_buffer(128)
    ip_string_size = ctypes.c_int(ctypes.sizeof(ip_string))

    if address_family == socket.AF_INET:
        if len(packed_ip) != ctypes.sizeof(addr.ipv4_addr):
            raise socket.error('packed IP wrong length for inet_ntoa')
        ctypes.memmove(addr.ipv4_addr, packed_ip, 4)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != ctypes.sizeof(addr.ipv6_addr):
            raise socket.error('packed IP wrong length for inet_ntoa')
        ctypes.memmove(addr.ipv6_addr, packed_ip, 16)
    else:
        raise socket.error('unknown address family')

    if WSAAddressToStringA(
            ctypes.byref(addr),
            addr_size,
            None,
            ip_string,
            ctypes.byref(ip_string_size)
    ) != 0:
        raise socket.error(ctypes.FormatError())

    return ip_string[:ip_string_size.value - 1]


def inet_to_str(inet):

    # return socket.inet_ntop(socket.AF_INET, inet)
    return inet_ntop(socket.AF_INET, inet)


def check_value(src, dst, srcList, dstList, valueList):
    flag = 0
    for index, value in enumerate(srcList):
        if src == value:
            if dst == dstList[index]:
                valueList[index] += 1
                flag = 1
                break
        elif dst == value:
            if src == dstList[index]:
                valueList[index] += 1
                flag = 1
                break
    if flag == 0:
        srcList.append(src)
        dstList.append(dst)
        valueList.append(1)
    return srcList, dstList, valueList


# Get the required data
def get_IP_List(pcap, srcList,  dstList,  valueList):
    packet_num = 0
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        # Filter out packets without IP segments
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        ip_src = inet_to_str(ip.src)
        ip_dst = inet_to_str(ip.dst)

        packet_num = packet_num + 1

        srcList, dstList, valueList = check_value(ip_src, ip_dst, srcList, dstList, valueList)
        # print('{0}\ttime:{1}\tsrc:{2}=>dst:{3} '.format(packet_num,timestamp,ip_src ,ip_dst))
        # print('{0}\tsrc:{1}=>dst:{2} '.format(packet_num, ip_src, ip_dst))

        if eth.data.__class__.__name__ == 'IP':
            ip = '%d.%d.%d.%d' % tuple(list(eth.data.dst))
            if eth.data.data.__class__.__name__ == 'TCP':
                if eth.data.data.dport == 80:
                    # HTTP requested data
                    # print(eth.data.data.data)
                    pass
    return srcList, dstList, valueList


# Call the write module to write data to CSV
def solve(pcapPath, csvPath):
    f = open(pcapPath, 'rb')
    pcap = dpkt.pcap.Reader(f)
    src_ip = []
    dst_ip = []
    value_ip = []
    src_ip, dst_ip, value_ip = get_IP_List(pcap, src_ip, dst_ip, value_ip)
    Temp = [list(i) for i in zip(src_ip, dst_ip, value_ip)]
    write_text_clean('Source,Target,Weight', csvPath)
    for i in Temp:
        write_text("{0},{1},{2}".format(str(i[0], encoding="utf-8"), str(i[1], encoding="utf-8"), i[2]),
                   csvPath)


if __name__ == '__main__':
    solve('../../test/test3.pcap', '../../test/test.csv')