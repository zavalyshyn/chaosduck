import sys


def check_or_fail(condition, msg):
    """Assert that the condition holds and if not exit with the error message.

    :param condition: the boolean condition
    :param msg: the message printed on stderr
    """
    if not condition:
        if 'Target value out of range : ' not in msg:
            sys.stderr.write(msg + "\n")
        exit(-1)


def set_bytes(outfile, start_addr, value=0, nb_repeat=1):
    """Write a 8-bit value several times in a file starting at a specified offset.

    :param outfile: the IO stream of the file
    :param start_addr: the offset in the file
    :param value: the byte value as an integer 0-255
    :param nb_repeat: number of repetitions
    """
    outfile.seek(start_addr)
    outfile.write(bytes([value] * nb_repeat))


# def set_bit(outfile, addr, significance, value):
#     check_or_fail(0 <= significance < 8, "The significance of the bit must be between 0 and 7 : " + str(significance))
#     check_or_fail(value == 0 or value == 1, "The value is not binary : " + str(value))
#     outfile.seek(addr)
#     prev_value = ord(outfile.read(1))
#     if value == 0:
#         prev_value &= ~(1 << significance)
#     else:
#         prev_value |= (1 << significance)
#     set_bytes(outfile, addr, prev_value)


def bits_list(bytes_l):
    """Transform a list of byte offsets to a list of bit offsets.

    :param bytes_l: list of offsets (integer)
    :return: a list
    """
    bits_l = []
    for i in bytes_l:
        bits_l.extend(range(i * 8, i * 8 + 8))
    return bits_l


def parse_addr(addr):
    """Parse a string representing an address or a range of addresses to an list of integer address(es).
    Exit with error if format is wrong.

    :param addr: the string to parse
    :return: a list of adresses
    """
    try:
        return [int(addr, 0)]
    except ValueError:
        borders = addr.split('-')
        try:
            check_or_fail(len(borders) == 2, "Wrong address format : " + addr)
            ret = list(range(int(borders[0], 0), int(borders[1], 0) + 1))  # inclusive borders
            check_or_fail(len(ret) > 0, "Address range empty : " + addr)
            return ret
        except ValueError:
            check_or_fail(False, "Wrong address format : " + addr)
