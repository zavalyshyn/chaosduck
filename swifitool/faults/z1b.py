from faults.faultmodel import FaultModel
from utils import *


class Z1B(FaultModel):
    name = 'Z1B'
    docs = '    Z1B addr \t\t\t set one byte to 0x0'
    nb_args = 1

    def __init__(self, config, args):
        super().__init__(config, args)
        self.addr = parse_addr(args[0])

    def edited_memory_locations(self):
        return bits_list(self.addr)

    def apply(self, opened_file):
        set_bytes(opened_file, self.addr[0], nb_repeat=len(self.addr))
