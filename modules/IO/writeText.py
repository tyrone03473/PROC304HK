# -*- coding: utf-8 -*-

def write_text(strings: str, filepath: str) -> None:
    # The path of strings is PCAP.
    # The path of filepath is TEXT's path.

    ftxt = open(filepath, 'a')
    ftxt.write(strings + '\n')
    ftxt.close()
    return None

def write_text_clean(strings: str, filepath: str) -> None:
    # The path of strings is PCAP.
    # The path of filepath is TEXT's path.

    ftxt = open(filepath, 'w')
    ftxt.write(strings + '\n')
    ftxt.close()
    return None

if __name__ == '__main__':
    write_text("test", "../../test/test.txt")

