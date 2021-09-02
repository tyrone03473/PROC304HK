# -*- coding: utf-8 -*-
import modules.DataCleaning.solve
import modules.DataCleaning.parsePcap
import modules.IO.pyvisNetwork


if __name__ == '__main__':
    # Output and parse pcap packets
    modules.DataCleaning.parsePcap.parsePcap('test/test.pcap')
    # Parse the source IP, destination IP and value values of pcap file packets
    # where value is the number of interactions between IPS, and write the parsed value to the specified CSV file
    try:
        modules.DataCleaning.solve.solve('test/test.pcap', 'test/test.csv')
        print("="*60)
        print("Writing...")
    except:
        print("Writing failed...")

    print("=" * 60)
    print("Write succeeded, drawing in progress...")
    try:
        modules.IO.pyvisNetwork.show_html('test/test.csv')
        print("Drawing succeeded...")
    except:
        print("Drawing failed...")
