import sys, os, shlex, time, csv, shutil
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import *
from capstone.x86 import *
from pathlib import Path
from subprocess import Popen,PIPE,TimeoutExpired
from multiprocessing import Pool
from functools import partial

sys.path.insert(1, 'swifitool') # use swifitool folder for file exports

from faults_inject import ExecConfig
from faults.jbe import JBE
from faults.jmp import JMP
from faults.z1b import Z1B
from faults.z1w import Z1W
from faults.nop import NOP
from faults.flp import FLP

def extract_x86_instructions(infile):
    print("Disassembling the binary and parsing instructions...\n");
    infile = open(infile, 'rb')
    # ELFFile looks for magic number, if there's none, ELFError is raised
    try:
        elffile = ELFFile(infile)
        parsing = False
        startAddress = 65535
        endAddress = 0
        # all jump instr supported by Intel x86 CPU
        supjumps = ['jne','je','jbe','jae','jb','jo','jmp','ja','jle','js','jc',
        'jcxz','jecxz','jrcxz','jg','jge','jl','jle','jna','jnae','jnbe','jnc',
        'jng','jnge','jnl','jnle','jno','jnp','jns','jnz','jp','jpe','jpo','jz']
        jumps = []  # array for jmp instructions
        cmpsmovs = []   # array for cmp and mov instructions
        allinstr = []   # all instructions' addresses and their size in bytes
        for section in elffile.iter_sections():
            ops = section.data()
            addr = section['sh_addr']
            name = section.name
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = True
            # print("%x\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            # print("%x:\t%s\t%s\t" %(i.address, i.mnemonic, i.op_str) +
              # ' '.join(format(x, '02x') for x in i.bytes)) # with bytes
            # below code finds and parses only certain elf sections
            # this is consistent with "objdump -S binary" command output
            if name == ".rodata": parsing = False
            elif name == ".init" or parsing:
                parsing = True
                for i in md.disasm(ops, addr):
                    # determine the heap range
                    if i.address < startAddress: startAddress=i.address
                    if i.address > endAddress: endAddress=i.address
                    allinstr.append({'addr':i.address, 'size':i.size})
                    # print("%x\t%s\t%s\t%d" %(i.address, i.mnemonic, i.op_str, i.size))
                    # determine the instruction type and parse accordingly
                    if i.mnemonic in supjumps:  # select only jump instructions
                        if len(i.op_str)==6: # process only simple jumps e.g 0x3eef
                            # print("%x\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                            type = i.mnemonic
                            jumpfrom = hex(i.address) # 0xdead
                            jumpto = i.op_str   # 0xbeef
                            jump = {'type':type, 'from':jumpfrom, 'to':jumpto}
                            jumps.append(jump)
                    # zero static compare values and static variables
                    elif i.mnemonic == 'cmp' or i.mnemonic =='mov':  # select cmp or mov instructions
                        # print("%x:\t%s\t%s\t%d" %(i.address, i.mnemonic, i.op_str, i.size))
                        lastoperand = i.operands[len(i.operands)-1]
                        operands = i.op_str.split()
                        value = operands[len(operands)-1]
                        # ignore comparisons with zero and values stored in registers
                        if value!='0' and ']' not in value and lastoperand.type!=X86_OP_REG:
                            # print("%x:\t%s\t%s\t%d" %(i.address, i.mnemonic, i.op_str, i.size))
                            size = 0
                            loc = 0
                            if len(value)<=4:   # '0x' + 1 byte i.e. max 255
                                size = 1
                                if 'byte' in operands:
                                    loc = hex(i.address + (i.size - 1))
                                elif 'word' in operands:
                                    loc = hex(i.address + (i.size - 2)) # 2 bytes
                                elif 'dword' in operands:
                                    loc = hex(i.address + (i.size - 4)) # 4 bytes
                            elif len(value)<=6: # '0x' + 2 bytes i.e. uint16_t
                                size = 2
                                if 'word' in operands:
                                    loc = hex(i.address + (i.size - 2)) # 2 bytes
                                elif 'dword' in operands:
                                    loc = hex(i.address + (i.size - 4)) # 4 bytes
                            elif len(value)<=10: # '0x' + 4 bytes i.e. uint32_t or int
                                size = 4
                                if 'dword' in operands:
                                    loc = hex(i.address + (i.size - 4)) # 4 bytes
                            if loc!=0:
                                cmpsmovs.append({'type':i.mnemonic,'size':size,'loc':loc})
        return allinstr, jumps, cmpsmovs
    except ELFError:
        logging.info("%s is invalid elf file" % elffile)

def extract_arm_instructions(infile):
    print("Disassembling the binary and parsing instructions...\n");
    infile = open(infile, 'rb')
    # ELFFile looks for magic number, if there's none, ELFError is raised
    try:
        elffile = ELFFile(infile)
        parsing = False
        startAddress = 65535
        endAddress = 0
        # all ARM branch instructions
        branch_instr = ['b', 'beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi','bpl',
        'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'bl', 'bleq',
        'bllt', 'blx', 'bx', 'bxeq', 'bxne', 'bxcs', 'bxcc', 'bxhi', 'bxls',
        'bxgt', 'bxle']
        jumps = []  # array for jmp instructions
        cmpsmovs = []   # array for cmp and mov instructions
        allinstr = []   # all instructions' addresses and their size in bytes
        for section in elffile.iter_sections():
            ops = section.data()
            addr = section['sh_addr']   # section start address
            offset = section['sh_offset']
            file_offset = addr - offset
            name = section.name
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            # below code finds and parses only certain elf sections
            # this is consistent with "objdump -S binary" command output
            if name == ".rodata": parsing = False
            elif name == ".init" or parsing:
                parsing = True
                for i in md.disasm(ops, addr):
                    # determine the heap range
                    if i.address < startAddress: startAddress=i.address
                    if i.address > endAddress: endAddress=i.address
                    allinstr.append({'addr':i.address-file_offset, 'size':i.size})
                    # determine the instruction type and parse accordingly
                    if i.mnemonic in branch_instr:  # select only branch instructions
                        if len(i.op_str)>4: # process proper jump addresses and ignore registers
                            type = i.mnemonic
                            jumpfrom = hex(i.address-file_offset)
                            jumpto = hex(int(i.op_str.split('#')[1],0)-file_offset) # remove # from '#0x14f30'
                            jump = {'type':type, 'from':jumpfrom, 'to':jumpto}
                            jumps.append(jump)
                    # zero static compare values and static variables
                    elif i.mnemonic == 'cmp' or i.mnemonic =='mov':  # select cmp or mov instructions
                        operands = i.op_str.split()
                        op_value = operands[len(operands)-1]
                        # ignore comparisons with zero and values stored in registers
                        if op_value!='#0' and '#' in op_value:
                            val = op_value.split('#')[1]
                            loc = hex(i.address)
                            if len(val)<=4:   # '0x' + 1 byte i.e. max 255
                                size = 1
                            elif len(val)<=6: # '0x' + 2 bytes
                                size = 2
                            cmpsmovs.append({'type':i.mnemonic,'size':size,'loc':loc})
        return allinstr, jumps, cmpsmovs
    except ELFError:
        logging.info("%s is invalid elf file" % elffile)

def inject_jump_faults(jumps,allinstr,infile,arch):
    # General configuration
    config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
    # prepare the fault models
    fm_list = []
    jump_targets = [j['to'] for j in jumps]
    jump_targets = list(dict.fromkeys(jump_targets)) # remove duplicates
    # try valid jump targets from the existing ones
    # for jump in jumps:
    #     for target in jump_targets:
    #         if target!=jump['to']:
    #             try:
    #                 if jump['type'] == ('jmp' or 'b'):
    #                     fault = {'type':jump['type'],'at':jump['from'],
    #                         'from':jump['to'],'to':target,
    #                         'fault':JMP(config, [jump['from'],target])}
    #                 else:
    #                     fault = {'type':jump['type'],'at':jump['from'],
    #                         'from':jump['to'],'to':target,
    #                         'fault':JBE(config, [jump['from'],target])}
    #                 fm_list.append(fault)
    #             except SystemExit:
    #                 pass # skip targets causing out of range erors and move on
    # try setting jump targets to all possible instruction addresses
    # this includes jumping in the middle of an instruction
    for jump in jumps:
        for target in allinstr:
            if target['addr']!=jump['to']:
                try:
                    for offset in range(0,target['size']):
                        loc = hex(target['addr']+offset)
                        if jump['type'] == ('jmp' or 'b'):
                            if offset>0:
                                type = jump['type'] + '_middlejmp'
                                print(type)
                                fault = {'type':type,'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JMP(config,[jump['from'],loc])}
                            else:
                                fault = {'type':jump['type'],'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JMP(config,[jump['from'],loc])}
                        else:
                            if offset>0:
                                type = jump['type'] + '_middlejmp'
                                fault = {'type':type,'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JBE(config,[jump['from'],loc])}
                            else:
                                fault = {'type':jump['type'],'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JBE(config, [jump['from'],loc])}
                        fm_list.append(fault)
                except SystemExit:
                    pass # skip targets causing out of range erors and move on

    print("Number of detected jumps: ", len(jumps))
    print("Number of new binaries with changed jumps: ", len(fm_list))
    # create a folder for faulted binaries
    Path("faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for f in fm_list:
        outfile = 'faulted-binaries/%s_at_%s_from_%s_to_%s' %(f['type'],
        f['at'],f['from'],f['to'])
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def inject_zero_faults(targets,infile,arch):
    # prepare the fault models
    fm_list = []
    for target in targets:
        try:
            if target['size'] == 1:
                config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
                fault = {'type':target['type'], 'loc':target['loc'], 'fault':Z1B(config,[target['loc']])}
                fm_list.append(fault)
            else:
                config = ExecConfig(os.path.expanduser(infile), None, arch, target['size'])
                fault = {'type':target['type'], 'loc':target['loc'], 'fault':Z1W(config,[target['loc']])}
                fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of locations to zero: ", len(targets))
    print("Number of new binaries with zeroed values: ", len(fm_list))
    # create a folder for faulted binaries
    Path("faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for f in fm_list:
        outfile = 'faulted-binaries/%s_at_%s_zeroed' %(f['type'],f['loc'])
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def inject_nop_faults(targets, infile, arch):
    # prepare the fault models
    fm_list = []
    for target in targets:
        try:
            config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
            addr_from = target['addr']
            addr_till = target['addr'] + target['size'] - 1
            noprange = hex(addr_from) + '-' + hex(addr_till)
            # print("From %x till %x = Range %s" %(addr_from,addr_till,range))
            fault = {'range':noprange, 'fault':NOP(config,[noprange])}
            fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of instructions to be NOPed: ", len(targets))
    print("Number of new binaries with NOPed instructions: ", len(fm_list))
    # create a folder for faulted binaries
    Path("faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for f in fm_list:
        outfile = 'faulted-binaries/nop_%s' %f['range']
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def inject_flp_faults(targets, infile, arch):
    # prepare the fault models
    fm_list = []
    for target in targets:
        try:
            config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
            addr_from = target['addr']
            for offset in range(0,target['size']):
                loc = hex(addr_from+offset)

                # with static significance bit
                # sgnf = 5
                # fault = {'loc':loc, 'sgnf':sgnf, 'fault':FLP(config,[loc,sgnf])}
                # fm_list.append(fault)

                # or with varied significance bit
                for sgnf in range(0,8):
                    fault = {'loc':loc, 'sgnf':sgnf, 'fault':FLP(config,[loc,sgnf])}
                    fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of instructions to be FLPed: ", len(targets))
    print("Number of new binaries with FLPed instructions: ", len(fm_list))
    # create a folder for faulted binaries
    Path("faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for f in fm_list:
        outfile = 'faulted-binaries/flp_at_%s_sgnf_%d' %(f['loc'],f['sgnf'])
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def run_faulty_binaries(infile,arch):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    keys = ["00010203040506070809","01234567890987654321","deadbeafdeadc0debabe"]
    plaintexts = ["badf00dbadc0ffee","deadbeafbabec0de","1ceb00dab10sf00d"]
    with open('results.csv', 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        faulty_binaries_list = os.listdir("faulted-binaries")
        batchsize = 1000 # execute files in batches of 1000
        for key in keys:
            for plaintext in plaintexts:
                print("Using key %s and plaintext %s" %(key,plaintext))
                # function to run the faulty binaries
                func = partial(execute_file, key, plaintext, arch)  # hack to pass more than 1 argument to execute_file function
                for i in range(0, len(faulty_binaries_list), batchsize):
                    batch = faulty_binaries_list[i:i+batchsize]
                    with Pool(processes=50) as pool:
                        results = pool.imap(func, batch)
                        pool.close()
                        for res in results:
                            # if '0xba 0xdf 0x00 0xdb 0xad 0xc0 0xff 0xee' in res['stdout']:
                            # if b'0xba 0xdf 0x00 0xdb 0xad 0xc0 0xff 0xee' in res['stdout']:
                                # print("BINGO! Plaintext instead of cipher in",res['filename'])
                            writer.writerow([infile,res['filename'],key,plaintext,res['stdout'],res['stderr'],
                                res['exitcode'],res['timedout']])


def execute_file(key, plaintext, arch, filename):
    if arch=='x86':
        command = 'faulted-binaries/%s %s %s' %(filename,key,plaintext)
    elif arch=='arm':
        command = 'qemu-arm -L /usr/arm-linux-gnueabi/ faulted-binaries/%s %s %s' %(filename,key,plaintext)
    args = shlex.split(command)
    # p = Popen(args,stdout=PIPE,stderr=PIPE,universal_newlines=True) # extract stdout in a textual utf-8 format
    p = Popen(args,stdout=PIPE,stderr=PIPE) # extract stdout in a binary-like format
    try:
        outs, errs = p.communicate(timeout=3)   # 3 sec
        # print(filename,outs,errs,p.returncode)
        return({'filename':filename,'stdout':outs,'stderr':errs,
            'exitcode':p.returncode,'timedout':False})
    except TimeoutExpired:
        p.kill()
        outs, errs = p.communicate()
        # print(filename,outs,errs,p.returncode)
        return({'filename':filename,'stdout':outs,'stderr':errs,
            'exitcode':p.returncode,'timedout':True})
    finally:
        p.kill()

def main(argv):
    infile = argv[1]
    arch = argv[2]
    if arch=='x86':
        allinstr, jumps, cmpsmovs = extract_x86_instructions(infile)
    elif arch=='arm':
        allinstr, jumps, cmpsmovs = extract_arm_instructions(infile)
    print("Number of detected instructions: ", len(allinstr))
    inject_jump_faults(jumps,allinstr,infile,arch)
    inject_zero_faults(cmpsmovs,infile,arch)
    inject_nop_faults(allinstr,infile,arch)
    inject_flp_faults(allinstr,infile,arch)
    run_faulty_binaries(infile,arch)


if __name__ == '__main__':
    main(sys.argv)
