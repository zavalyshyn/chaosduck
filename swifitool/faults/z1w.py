from faults.faultmodel import FaultModel
from utils import *


class Z1W(FaultModel):
    name = 'Z1W'
    docs = '    Z1W addr \t\t\t set one word to 0x0'
    nb_args = 1

    def __init__(self, config, args):
        super().__init__(config, args)
        self.addr = parse_addr(args[0])
        check_or_fail(config.word_length is not None, "Word size required when using Z1W")
        check_or_fail(len(self.addr) == 1 or len(self.addr) % config.word_length == 0,
                      "Range of addresses for Z1W must be multiple of the word length")

    def edited_memory_locations(self):
        if len(self.addr) == 1:
            return bits_list(range(self.addr[0], self.addr[0] + self.config.word_length))
        else:
            return bits_list(self.addr)

    def apply(self, opened_file):
        if len(self.addr) == 1:
            set_bytes(opened_file, self.addr[0], nb_repeat=self.config.word_length)
        else:
            set_bytes(opened_file, self.addr[0], nb_repeat=len(self.addr))
