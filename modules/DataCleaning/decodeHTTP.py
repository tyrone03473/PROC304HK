import dpkt


def checkIfHTTPRes(data):
    if len(data) < 4:
        return False

    if data[:4] == str.encode('HTTP'):
        return True
    return False


def httpPacketParser(http):
    if checkIfHTTPRes(http):
        try:
            response = dpkt.http.Response(http)
            print(response.status)

        except Exception as e:
            print("cannot get results")
            # print(e)
            pass


def tcpPacketParser(tcp):
    stream = tcp.data
    if len(stream):
        httpPacketParser(stream)
    else:
        pass


def ipPacketParser(ip):
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcpPacketParser(ip.data)


def decodePacket(packet):
    # Ethernet frame reading of data part
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        ipPacketParser(eth.data)


if __name__ == "__main__":
    pass
