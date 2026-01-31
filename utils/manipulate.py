import lief  # pip install https://github.com/lief-project/LIEF/releases/download/0.7.0/linux_lief-0.7.0_py3.6.tar.gz
import json
import os
import sys
import array
import struct  # byte manipulations
import random
import tempfile
import subprocess
import functools
import signal
import multiprocessing
# import angr
import networkx as nx


module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]

COMMON_SECTION_NAMES = open(os.path.join(
    module_path, 'section_names.txt'), 'r').read().rstrip().split('\n')
COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, 'small_dll_imports.json'), 'r'))


class MalwareManipulator(object):
    def __init__(self, bytez):
        self.bytez = bytez
        self.min_append_log2 = 5
        self.max_append_log2 = 8

    def __random_length(self):
        return 2 ** random.randint(self.min_append_log2, self.max_append_log2)

    def __binary_to_bytez(self, binary, dos_stub=False, imports=False, overlay=False, relocations=False,
                          resources=False, tls=False):
        builder = lief.PE.Builder(binary)
        builder.build_imports(imports)
        builder.build()

        self.bytez = array.array('B', builder.get_build()).tobytes()
        return self.bytez

    def overlay_append(self, seed=None):
        random.seed(seed)
        L = self.__random_length()
        # choose the upper bound for a uniform distribution in [0,upper]
        upper = random.randrange(256)
        # upper chooses the upper bound on uniform distribution:
        # upper=0 would append with all 0s
        # upper=126 would append with "printable ascii"
        # upper=255 would append with any character
        return self.bytez + bytes([random.randint(0, upper) for _ in range(L)])

    def imports_append(self, seed=None):
        ori_bytez = self.bytez
        try:
            # add (unused) imports
            random.seed(seed)
            binary = lief.parse(self.bytez)
            # draw a library at random
            libname = random.choice(list(COMMON_IMPORTS.keys()))
            funcname = random.choice(list(COMMON_IMPORTS[libname]))
            lowerlibname = libname.lower()
            # find this lib in the imports, if it exists
            lib = None
            for im in binary.imports:
                if im.name.lower() == lowerlibname:
                    lib = im
                    break
            if lib is None:
                # add a new library
                lib = binary.add_library(libname)
            # get current names
            names = set([e.name for e in lib.entries])
            if not funcname in names:
                lib.add_entry(funcname)
            self.bytez = self.__binary_to_bytez(binary, imports=True)
            return self.bytez
        except:
            print('import error')
            return ori_bytez


    def section_rename(self, seed=None):
        # rename a random section
        random.seed(seed)
        binary = lief.parse(self.bytez)
        targeted_section = random.choice(binary.sections)
        targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7]  # current version of lief not allowing 8 chars?

        self.bytez = self.__binary_to_bytez(binary)

        return self.bytez

    def section_add(self, seed=None):
        random.seed(seed)
        binary = lief.parse(self.bytez)
        new_section = lief.PE.Section(
            "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(6)))

        # fill with random content
        upper = random.randrange(256)
        L = self.__random_length()
        new_section.content = [random.randint(0, upper) for _ in range(L)]

        new_section.virtual_address = max(
            [s.virtual_address + s.size for s in binary.sections])
        # add a new empty section

        binary.add_section(new_section,
                           random.choice([
                               lief.PE.SECTION_TYPES.BSS,
                               lief.PE.SECTION_TYPES.DATA,
                               lief.PE.SECTION_TYPES.EXPORT,
                               lief.PE.SECTION_TYPES.IDATA,
                               lief.PE.SECTION_TYPES.RELOCATION,
                               lief.PE.SECTION_TYPES.RESOURCE,
                               lief.PE.SECTION_TYPES.TEXT,
                               lief.PE.SECTION_TYPES.TLS_,
                               lief.PE.SECTION_TYPES.UNKNOWN,
                           ]))

        self.bytez = self.__binary_to_bytez(binary)
        return self.bytez

    def section_append(self, seed=None):
        # append to a section (changes size and entropy)
        random.seed(seed)
        binary = lief.parse(self.bytez)
        targeted_section = random.choice(binary.sections)
        L = self.__random_length()
        available_size = targeted_section.size - len(targeted_section.content)
        if L > available_size:
            L = available_size

        upper = random.randrange(256)
        # Handle both list and array types
        if hasattr(targeted_section.content, 'tolist'):
            content_list = targeted_section.content.tolist()
        else:
            content_list = list(targeted_section.content) if not isinstance(targeted_section.content, list) else targeted_section.content
        targeted_section.content = content_list + \
                                   [random.randint(0, upper) for _ in range(L)]

        self.bytez = self.__binary_to_bytez(binary)
        return self.bytez

    # def section_reorder(self,param,seed=None):
    #   # reorder directory of sections
    #   pass

    def create_new_entry(self, seed=None):
        # create a new section with jump to old entry point, and change entry point
        # DRAFT: this may have a few technical issues with it (not accounting for relocations), but is a proof of concept for functionality
        random.seed(seed)

        binary = lief.parse(self.bytez)

        # get entry point
        entry_point = binary.optional_header.addressof_entrypoint

        # get name of section
        entryname = binary.section_from_rva(entry_point).name

        # create a new section
        new_section = lief.PE.Section(entryname + "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(3)))  # e.g., ".text" + 3 random characters
        # push [old_entry_point]; ret
        # new_section.content = [0x68] + list(struct.pack("<I", entry_point + 0x10000)) + [0xc3]
        new_section.content = [0x68] + list(struct.pack("<I", 0x411000)) + [0xc3]
        # print(list(struct.pack("<I", entry_point + 0x10000)))
        # print(entry_point + 0x10000)

        new_section.virtual_address = max([s.virtual_address + s.size for s in binary.sections])
        # TO DO: account for base relocation (this is just a proof of concepts)

        # add new section
        binary.add_section(new_section, lief.PE.SECTION_TYPES.TEXT)

        # redirect entry point
        binary.optional_header.addressof_entrypoint = new_section.virtual_address

        self.bytez = self.__binary_to_bytez(binary)
        return self.bytez

    def upx_pack(self, seed=None):
        # tested with UPX 3.91
        random.seed(seed)
        tmpfilename = os.path.join(
            tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

        # dump bytez to a temporary file
        with open(tmpfilename, 'wb') as outfile:
            outfile.write(self.bytez)

        options = ['--force', '--overlay=copy']
        compression_level = random.randint(1, 9)
        options += ['-{}'.format(compression_level)]
        # --exact
        # compression levels -1 to -9
        # --overlay=copy [default]

        # optional things:
        # --compress-exports=0/1
        # --compress-icons=0/1/2/3
        # --compress-resources=0/1
        # --strip-relocs=0/1
        options += ['--compress-exports={}'.format(random.randint(0, 1))]
        options += ['--compress-icons={}'.format(random.randint(0, 3))]
        options += ['--compress-resources={}'.format(random.randint(0, 1))]
        options += ['--strip-relocs={}'.format(random.randint(0, 1))]

        with open(os.devnull, 'w') as DEVNULL:
            retcode = subprocess.call(
                ['upx'] + options + [tmpfilename, '-o', tmpfilename + '_packed'], stdout=DEVNULL, stderr=DEVNULL)

        os.unlink(tmpfilename)

        if retcode == 0:  # successfully packed

            with open(tmpfilename + '_packed', 'rb') as infile:
                self.bytez = infile.read()

            os.unlink(tmpfilename + '_packed')

        return self.bytez

    def upx_unpack(self, seed=None):
        # dump bytez to a temporary file
        tmpfilename = os.path.join(
            tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

        with open(tmpfilename, 'wb') as outfile:
            outfile.write(self.bytez)

        with open(os.devnull, 'w') as DEVNULL:
            retcode = subprocess.call(
                ['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'], stdout=DEVNULL, stderr=DEVNULL)

        os.unlink(tmpfilename)

        if retcode == 0:  # sucessfully unpacked
            with open(tmpfilename + '_unpacked', 'rb') as result:
                self.bytez = result.read()

            os.unlink(tmpfilename + '_unpacked')

        return self.bytez

    def remove_signature(self, seed=None):
        random.seed(seed)
        binary = lief.parse(self.bytez)

        if hasattr(binary, 'has_signature'):
            for i, e in enumerate(binary.data_directories):
                if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
                    break
            if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
                # remove signature from certificate table
                e.rva = 0
                e.size = 0
                self.bytez = self.__binary_to_bytez(binary)
                return self.bytez
        # if no signature found, self.bytez is unmodified
        return self.bytez

    def remove_debug(self, seed=None):
        random.seed(seed)
        binary = lief.parse(self.bytez)

        if binary.has_debug:
            for i, e in enumerate(binary.data_directories):
                if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
                    break
            if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
                # remove signature from certificate table
                e.rva = 0
                e.size = 0
                self.bytez = self.__binary_to_bytez(binary)
                return self.bytez
        # if no signature found, self.bytez is unmodified
        return self.bytez

    def break_optional_header_checksum(self, seed=None):
        binary = lief.parse(self.bytez)
        binary.optional_header.checksum = 0
        self.bytez = self.__binary_to_bytez(binary)
        return self.bytez


##############################
def identity(bytez, seed=None):
    return bytez


######################
# explicitly list so that these may be used externally
ACTION_LIMIT = 2 ** 16
ACTIONS = {
    'overlay_append', 'imports_append', 
    'section_rename', 'section_add', 'section_append',
    'remove_signature', 'remove_debug',
    'create_new_entry', 
    'upx_pack', 'upx_unpack',
    'break_optional_header_checksum'
}

ACTION_TABLE = {k: ACTION_LIMIT for k in ACTIONS}
ACTION_TABLE['remove_debug'] = 1
ACTION_TABLE['remove_signature'] = 1
ACTION_TABLE['break_optional_header_checksum'] = 1

def modify_without_breaking(bytez, actions=None, seed=None):
    actions = actions or []
    for _action in actions:

        # we run manipulation in a child process to shelter
        # our malware model from rare parsing errors in LIEF that
        # may segfault or timeout
        def helper(_action, shared_list):
            # TODO: LIEF is chatty. redirect stdout and stderr to /dev/null

            # for this process, change segfault of the child process
            # to a RuntimeEror
            def sig_handler(signum, frame):
                raise RuntimeError

            signal.signal(signal.SIGSEGV, sig_handler)

            bytez = array.array('B', shared_list[:]).tobytes()
            # TODO: LIEF is chatty. redirect output to /dev/null
            if type(_action) is str:
                _action = MalwareManipulator(bytez).__getattribute__(_action)
            else:
                _action = functools.partial(_action, bytez)

            # redirect standard out only in this queue
            try:
                shared_list[:] = _action(seed)
            except (RuntimeError, UnicodeDecodeError, TypeError, lief.not_found) as e:
                # some exceptions that have yet to be handled by public release of LIEF
                print(f"==== exception in child process when {_action.__name__} ====")
                print(e)
                # shared_bytez remains unchanged

        # communicate with the subprocess through a shared list
        # can't use multiprocessing.Array since the subprocess may need to
        # change the size
        manager = multiprocessing.Manager()
        shared_list = manager.list()
        shared_list[:] = bytez  # copy bytez to shared array
        # define process
        p = multiprocessing.Process(target=helper, args=(_action, shared_list))
        p.start()  # start the process
        try:
            p.join(5)  # allow this to take up to 5 seconds...
        except multiprocessing.TimeoutError:  # ..then become petulant
            print('==== timeouterror ')
            p.terminate()

        bytez = array.array('B', shared_list[:]).tobytes()  # copy result from child process
        p.terminate()
    # import hashlib
    # m = hashlib.sha256()
    # m.update(bytez)
    # print("new hash: {}".format(m.hexdigest()))
    return bytez

ACTION_TABLE_SRL = {
    'nop': 'nop',
    'sub': 'sub',
    'add': 'add',
    'lea': 'lea',
    'mov': 'mov',
    'xchg': 'xchg',
    'cmovo': 'cmovo',
    'cmovp': 'cmovp',
    'cmova': 'cmova',
    'cmovg': 'cmovg',
    'cmovs': 'cmovs',
    'cmovl': 'cmovl',
    'cmovns': 'cmovns',
    'cmovnp': 'cmovnp',
    'cmovno': 'cmovno',
        'add_sub': 'add_sub',
        'sub_add': 'sub_add',
    'neg_neg': 'neg_neg',
    'not_not': 'not_not',
    'push_pop': 'push_pop',
        'pushf_popf': 'pushf_popf',
        'xchg_xchg': 'xchg_xchg',
    'bswap_bswap': 'bswap_bswap',
        'push_not_pop': 'push_not_pop',
        'xor_xor_xor': 'xor_xor_xor',
        'mov_add_mov': 'mov_add_mov',
        'inc_push_dec_dec': 'inc_push_dec_dec',
        'mov_cmp_setg_movzx_mov_mov': 'mov_cmp_setg_movzx_mov_mov'
}
# ! 'nop', 'lea', 'xchg', 'neg', 'not', 'push', 'pop', 'pushf', 'popf', 'bswap', 'setg', 

SEMNOPS_TABLE = {
    'nop': ['nop'],
    'sub': ['sub'],
    'add': ['add'],
    'lea': ['lea'],
    'mov': ['mov'],
    'xchg': ['xchg'],
    'cmovo': ['cmovo'],
    'cmovp': ['cmovp'],
    'cmova': ['cmova'],
    'cmovg': ['cmovg'],
    'cmovs': ['cmovs'],
    'cmovl': ['cmovl'],
    'cmovns': ['cmovns'],
    'cmovnp': ['cmovnp'],
    'cmovno': ['cmovno'],
        'add_sub': ['add', 'sub'],
        'sub_add': ['sub', 'add'],
    'neg_neg': ['neg', 'neg'],
    'not_not': ['not', 'not'],
    'push_pop': ['push', 'pop'],
        'pushf_popf': ['pushf', 'popf'],
        'xchg_xchg': ['xchg', 'xchg'],
    'bswap_bswap': ['bswap', 'bswap'],
        'push_not_pop': ['push','not','pop'],
        'xor_xor_xor': ['xor','xor','xor'],
        'mov_add_mov': ['mov','add','mov'],
        'inc_push_dec_dec': ['inc','push','dec','dec'],
        'mov_cmp_setg_movzx_mov_mov': ['mov','cmp','setg','movzx','mov','mov']
}

def insertSemanticNops(Instruction, topk_indices, node_info, op_encode, block_num):
    '''
    Inert Semantic Nops Instructions into basic block
    '''
    with open('/OpenMalAttack/configs/opcodeMap.json') as f:
        opcodeMap = json.load(f)

    Indx = [op_encode[ins] for ins in Instruction]
    increase_insn = len(Indx) # sum([random.choice(opcodeMap[ins]) for ins in Instruction])
    
    assert block_num >= len(topk_indices)
    assert (topk_indices < block_num).all().item()

    for i in topk_indices:
        for idx in Indx:
            node_info[i][idx] += 1

    return node_info, increase_insn

def manipulate_PEFile(args, block_num):
    PEAct, topk, Insn, node_info, op_encode = args
    if PEAct == 'insertSemanticNops':
        return insertSemanticNops(SEMNOPS_TABLE[Insn], topk, node_info, op_encode, block_num)
    else:
        print('Wrong Actions!')
        return None


def test(bytez):
    binary = lief.parse(bytez)


    print('create_new_entry')  # note: also adds a new section
    manip = MalwareManipulator(bytez)
    bytez2 = manip.create_new_entry(bytez)
    binary2 = lief.parse(bytez2)
    print(binary.entrypoint)
    print(binary2.entrypoint)
    assert binary.entrypoint != binary2.entrypoint, "no new entry point"
    return bytez2
