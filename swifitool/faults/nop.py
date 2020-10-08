from faults.faultmodel import FaultModel
from utils import *


class NOP(FaultModel):
    name = 'NOP'
    docs = '    NOP addr \t\t\t nop one address (1 or 2 bytes depending on arch)'
    nb_args = 1

    def __init__(self, config, args):
        super().__init__(config, args)
        self.addr = parse_addr(args[0])
        check_or_fail(config.arch is not None, "Architecture required when using NOP")
        if self.config.arch == 'arm' and len(self.addr) != 1:
            check_or_fail(len(self.addr) % 2 == 0, "Range of addresses for NOP must be multiple of two on ARM")

    def edited_memory_locations(self):
        if len(self.addr) == 1:
            if self.config.arch == 'x86':
                return bits_list(self.addr)
            else:
                return bits_list(range(self.addr[0], self.addr[0] + 2))
        else:
            return bits_list(self.addr)

    def apply(self, opened_file):
        if self.config.arch == 'x86':
            set_bytes(opened_file, self.addr[0], 0x90, nb_repeat=len(self.addr))
        else:
            if len(self.addr) == 1:
                set_bytes(opened_file, self.addr[0], 0b00000000)
                set_bytes(opened_file, self.addr[0] + 1, 0b10111111)
            else:
                for i in range(len(self.addr) // 2):
                    set_bytes(opened_file, self.addr[0] + 2 * i, 0b00000000)
                    set_bytes(opened_file, self.addr[0] + 2 * i + 1, 0b10111111)
