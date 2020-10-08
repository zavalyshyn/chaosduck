from faults.faultmodel import FaultModel
from utils import *


class FLP(FaultModel):
    name = 'FLP'
    docs = '    FLP addr significance \t flip one specific bit'
    nb_args = 2

    def __init__(self, config, args):
        super().__init__(config, args)
        self.addr = parse_addr(args[0])
        check_or_fail(len(self.addr) == 1, "FLP does not support address range")
        try:
            # self.significance = int(args[1], 0)
            self.significance = args[1] # changed to avoid using strings
            check_or_fail(0 <= self.significance < 8,
                          "Significance must be between 0 and 7 : " + str(self.significance))
        except ValueError:
            check_or_fail(False, "Wrong significance format : " + args[1])

    def edited_memory_locations(self):
        return [self.addr[0] * 8 + self.significance]

    def apply(self, opened_file):
        opened_file.seek(self.addr[0])
        prev_value = ord(opened_file.read(1))
        prev_value ^= (1 << self.significance)
        set_bytes(opened_file, self.addr[0], prev_value)
