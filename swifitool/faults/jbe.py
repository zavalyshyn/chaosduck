import os

from faults.faultmodel import FaultModel
from utils import *


class JBE(FaultModel):
    name = 'JBE'
    docs = '    JBE addr target \t\t change the conditional jump to point on the target'
    nb_args = 2

    def __init__(self, config, args):
        super().__init__(config, args)
        self.addr = parse_addr(args[0])
        check_or_fail(len(self.addr) == 1, "Range of addresses not supported with JBE")
        check_or_fail(config.arch is not None, "Architecture required when using JBE")
        absolute_target = None
        try:
            absolute_target = int(args[1], 0)
        except ValueError:
            check_or_fail(False, "Invalid target for JBE : " + args[1])
        check_or_fail(0 <= absolute_target < os.stat(config.infile).st_size, "Target outside the file")
        f = open(self.config.infile, 'rb')
        f.seek(self.addr[0])
        if self.config.arch == 'x86':
            b0 = ord(f.read(1))
            b1 = ord(f.read(1))
            b2 = ord(f.read(1))
            if 0x70 <= b0 <= 0x7F or b0 == 0xE3:  # there might be a prefix 0x67 before 0xE3
                self.target = absolute_target - (self.addr[0] + 1 + 1)
                check_or_fail(-2 ** 7 <= self.target < 2 ** 7, "Target value out of range : " + str(self.target))
                self.type = 0
            elif b0 == 0x0F and 0x80 <= b1 <= 0x8F:
                try:
                    f.seek(self.addr[0] - 1)
                    b_prev = ord(f.read(1))
                except ValueError:
                    b_prev = 0
                if b_prev == 0x66:
                    self.addr = [self.addr[0] - 1]
                    self.target = absolute_target - (self.addr[0] + 3 + 2)
                    check_or_fail(-2 ** 15 <= self.target < 2 ** 15, "Target value out of range : " + str(self.target))
                    self.type = 2
                else:
                    self.target = absolute_target - (self.addr[0] + 2 + 4)
                    check_or_fail(-2 ** 31 <= self.target < 2 ** 31, "Target value out of range : " + str(self.target))
                    self.type = 1
            elif b0 == 0x66 and b1 == 0x0F and 0x80 <= b2 <= 0x8F:
                self.target = absolute_target - (self.addr[0] + 3 + 2)
                check_or_fail(-2 ** 15 <= self.target < 2 ** 15, "Target value out of range : " + str(self.target))
                self.type = 2
            else:
                check_or_fail(False, "Unknown opcode at JBE address : " + hex(b0))
        elif self.config.arch == 'arm':
            f.seek(self.addr[0] + 3)
            b3 = ord(f.read(1))
            if b3 & 0x0E == 0x0A:
                self.target = absolute_target - (self.addr[0] + 8)
                check_or_fail(-2 ** 25 <= self.target < 2 ** 25, "Target value out of range : " + str(self.target))
                self.type = 3  # B or BL
            else:
                check_or_fail(False, "Unknown opcode at JBE address : " + hex(b3))
        f.close()

    def edited_memory_locations(self):
        if self.type == 0:
            return bits_list(range(self.addr[0] + 1, self.addr[0] + 2))
        elif self.type == 1:
            return bits_list(range(self.addr[0] + 2, self.addr[0] + 6))
        elif self.type == 2:
            return bits_list(range(self.addr[0] + 3, self.addr[0] + 5))
        elif self.type == 3:
            return bits_list(range(self.addr[0], self.addr[0] + 3))

    def apply(self, opened_file):
        if self.type == 0:
            opened_file.seek(self.addr[0] + 1)
            opened_file.write(bytes([self.target & 0xFF]))
        elif self.type == 1:
            opened_file.seek(self.addr[0] + 2)
            opened_file.write(bytes([self.target & 0xFF]))
            opened_file.write(bytes([self.target >> 8 & 0xFF]))
            opened_file.write(bytes([self.target >> 16 & 0xFF]))
            opened_file.write(bytes([self.target >> 24 & 0xFF]))
        elif self.type == 2:
            opened_file.seek(self.addr[0] + 3)
            opened_file.write(bytes([self.target & 0xFF]))
            opened_file.write(bytes([self.target >> 8 & 0xFF]))
        elif self.type == 3:
            opened_file.seek(self.addr[0])
            opened_file.write(bytes([self.target >> 2 & 0xFF]))
            opened_file.write(bytes([self.target >> 10 & 0xFF]))
            opened_file.write(bytes([self.target >> 18 & 0xFF]))
