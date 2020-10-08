import argparse
import shutil
import sys
import os

from faults.flp import FLP
from faults.jbe import JBE
from faults.jmp import JMP
from faults.nop import NOP
from faults.z1b import Z1B
from faults.z1w import Z1W
from utils import check_or_fail


class ExecConfig:
    """Keeps the configuration variables."""

    def __init__(self, infile, outfile, arch, word_length):
        super().__init__()
        self.infile = infile
        self.outfile = outfile
        self.arch = arch
        self.word_length = word_length


def main(argv):
    fault_models = {'FLP': FLP, 'Z1B': Z1B, 'Z1W': Z1W, 'NOP': NOP, 'JMP': JMP, 'JBE': JBE}

    # Collect parameters
    parser = argparse.ArgumentParser(description='Software implemented fault injection tool',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--infile', type=str, metavar='INFILE', required=True, help='path to the source file')
    parser.add_argument('-o', '--outfile', type=str, metavar='OUTFILE', required=True,
                        help='path to the destination file')
    parser.add_argument('-w', '--wordsize', type=int, metavar='WORDSIZE', required=False,
                        help='number of bytes in a word')
    parser.add_argument('-a', '--arch', type=str, metavar='ARCHITECTURE', required=False, choices=['x86', 'arm'],
                        help='architecture of the executable (x86 or arm)')
    parser.add_argument('-g', '--graphical', action='store_true', required=False,
                        help='open a window comparing the input and the output')
    parser.add_argument('-f', '--fromfile', type=str, metavar='FILE_MODELS', required=False,
                        help='read the faults models from a file instead of command line')
    parser.add_argument('fault_models', nargs='*', metavar='FAULT_MODEL',
                        help='one fault model followed by its parameters\n' +
                             'The possible models are :\n' + "\n".join([s.docs for s in fault_models.values()]) +
                             '\naddr can be a number or a range (number-number)')
    args = parser.parse_args(argv[1:])
    check_or_fail(args.wordsize is None or args.wordsize > 0, "Word size must be positive")

    # General configuration
    config = ExecConfig(os.path.expanduser(args.infile), os.path.expanduser(args.outfile), args.arch, args.wordsize)

    # Fault models asked
    if args.fromfile is not None:
        with open(args.fromfile, 'r') as ff:
            args.fault_models.extend(ff.read().split())
    check_or_fail(len(args.fault_models) >= 1, "No fault models provided")
    fm_list = []
    indices = [i for i, x in enumerate(args.fault_models) if fault_models.get(x) is not None]
    indices.append(len(args.fault_models))

    for i in range(len(indices) - 1):
        n = indices[i]
        fm_name = args.fault_models[n]
        fm_type = fault_models.get(fm_name)
        if fm_type is not None:
            check_or_fail(indices[i + 1] - n - 1 == fm_type.nb_args, "Wrong number of parameters for " + fm_name)
            ar = []
            for j in range(fm_type.nb_args):
                ar.append(args.fault_models[n + 1 + j])
            fm_list.append(fm_type(config, ar))

    # Check that the faults do not overlap and do not write outside the end of the file
    mem = {}
    max_bits = os.stat(config.infile).st_size * 8
    for f in fm_list:
        for m in f.edited_memory_locations():
            check_or_fail(0 <= m < max_bits, "Address outside file content : byte " + hex(m // 8))
            check_or_fail(mem.get(m) is None, "Applying two fault models at the same place : byte " + hex(m // 8))
            mem[m] = f.name

    # Duplicate the input and then apply the faults
    shutil.copy(config.infile, config.outfile)
    with open(config.outfile, "r+b") as file:
        for f in fm_list:
            f.apply(file)

    # Open a window for comparing the Input/Output with the faults highlighted
    if args.graphical:
        colors = {'FLP': 'turquoise', 'Z1B': 'green', 'Z1W': 'green2', 'NOP': 'red', 'JMP': 'orange', 'JBE': 'tomato'}
        import diff_ui
        diff_ui.diff_ui(config.infile, config.outfile, fm_list, colors)


if __name__ == '__main__':
    main(sys.argv)
