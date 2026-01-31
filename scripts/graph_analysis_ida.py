#coding:utf-8
# Functions of getting ACFG
import sys
sys.path.append('/root/anaconda3/envs/py2/lib/python2.7/site-packages')
from idautils import *
from idaapi import *
from idc import *
import jsonlines
import omegaconf

cfg_path = '../configs/attack_mal.yaml'
config = omegaconf.OmegaConf.load(cfg_path)

__MODIFY__ = True

def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

def get_all_contributes(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	print('length of blocks', len(blocks))
	if len(blocks) > 8999:
		return -1, -1, -1, -1
	else:
		return 0, 0, 0, 0

def getfunc_consts(func):
	strings = []
	consts = []
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	for bl in blocks:
		strs, conts = getBBconsts(bl)
		strings += strs
		consts += conts
	return strings, consts

def getConst(ea, offset):
	strings = []
	consts = []
	optype1 = GetOpType(ea, offset)
	if optype1 == o_imm:
		imm_value = GetOperandValue(ea, offset)
		
		if 0<= imm_value <= 10:
			consts.append(imm_value)
		else:
			if isLoaded(imm_value) and getseg(imm_value):
				str_value = GetString(imm_value)
				if str_value is None:
					str_value = GetString(imm_value+0x40000)
					if str_value is None:
						consts.append(imm_value)
					else:
						re = all(40 <= ord(c) < 128 for c in str_value)
						if re:
							strings.append(str_value)
						else:
							consts.append(imm_value)
				else:
					re = all(40 <= ord(c) < 128 for c in str_value)
					if re:
						strings.append(str_value)
					else:
						consts.append(imm_value)
			else:
				consts.append(imm_value)
	return strings, consts

def getBBconsts(bl):
	strings = []
	consts = []
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		strings_src, consts_src = getConst(inst_addr, 0)
		strings_dst, consts_dst = getConst(inst_addr, 1)
		strings += strings_src
		strings += strings_dst
		consts += consts_src
		consts += consts_dst
		try:
			strings_dst, consts_dst = getConst(inst_addr, 2)
			consts += consts_dst
			strings += strings_dst
		except:
			pass

		inst_addr = NextHead(inst_addr)
	return strings, consts

def getFuncCalls(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calCalls(bl)
		sumcalls += callnum
	return sumcalls

def getLogicInsts(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calLogicInstructions(bl)
		sumcalls += callnum
	return sumcalls

def getTransferInsts(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calTransferIns(bl)
		sumcalls += callnum
	return sumcalls

def getIntrs(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	sumcalls = 0
	for bl in blocks:
		callnum = calInsts(bl)
		sumcalls += callnum
	return sumcalls

def getLocalVariables(func):
	args_num = get_stackVariables(func.startEA)
	return args_num

def getBasicBlocks(func):
	blocks = [(v.startEA, v.endEA) for v in FlowChart(func)]
	return len(blocks)

def getIncommingCalls(func):
	refs = CodeRefsTo(func.startEA, 0)
	re = len([v for v in refs])
	return re


def get_stackVariables(func_addr):
    args = []
    stack = GetFrame(func_addr)
    if not stack:
            return 0
    firstM = GetFirstMember(stack)
    lastM = GetLastMember(stack)
    i = firstM
    while i <=lastM:
        mName = GetMemberName(stack,i)
        mSize = GetMemberSize(stack,i)
        if mSize:
                i = i + mSize
        else:
                i = i+4
        if mName not in args and mName and 'var_' in mName:
            args.append(mName)
    return len(args)



def calArithmeticIns(bl):
	x86_AI = {'add':1, 'sub':1, 'div':1, 'imul':1, 'idiv':1, 'mul':1, 'shl':1, 'dec':1, 'inc':1}
	mips_AI = {'add':1, 'addu':1, 'addi':1, 'addiu':1, 'mult':1, 'multu':1, 'div':1, 'divu':1}
	calls = {}
	calls.update(x86_AI)
	calls.update(mips_AI)
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calCalls(bl):
	calls = {'call':1, 'jal':1, 'jalr':1}
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calInsts(bl):
	start = bl[0]
	end = bl[1]
	ea = start
	num = 0
	while ea < end:
		num += 1
		ea = NextHead(ea)
	return num

def calLogicInstructions(bl):
	x86_LI = {'and':1, 'andn':1, 'andnpd':1, 'andpd':1, 'andps':1, 'andnps':1, 'test':1, 'xor':1, 'xorpd':1, 'pslld':1}
	mips_LI = {'and':1, 'andi':1, 'or':1, 'ori':1, 'xor':1, 'nor':1, 'slt':1, 'slti':1, 'sltu':1}
	calls = {}
	calls.update(x86_LI)
	calls.update(mips_LI)
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num


def calSconstants(bl):
	"""
	未使用
	"""
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in calls:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num


def calNconstants(bl):
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		optype1 = GetOpType(inst_addr, 0)
		optype2 = GetOpType(inst_addr, 1)
		if optype1 == 5 or optype2 == 5:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def retrieveExterns(bl, ea_externs):
	externs = []
	start = bl[0]
	end = bl[1]
	inst_addr = start
	while inst_addr < end:
		refs = CodeRefsFrom(inst_addr, 1)
		try:
			ea = [v for v in refs if v in ea_externs][0]
			externs.append(ea_externs[ea])
		except:
			pass
		inst_addr = NextHead(inst_addr)
	return externs

def calTransferIns(bl):
	x86_TI = {
		'jmp':1, 'jz':1, 'jnz':1, 'js':1, 'je':1, 'jne':1, 'jg':1, 'jle':1, 'jge':1, 'ja':1, 'jnc':1, 'jb':1,
		'jl':1, 'jnb':1, 'jno':1, 'jnp':1, 'jns':1,
		'jo':1, 'jp':1,
    	'loop':1, 'loope':1, 'loopne':1, 'loopw':1,
    	'loopwe':1, 'loopwne':1,
	}
	mips_TI = {'beq':1, 'bne':1, 'bgtz':1, "bltz":1, "bgez":1, "blez":1, 'j':1, 'jal':1, 'jr':1, 'jalr':1}
	arm_TI = {'MVN':1, "MOV":1}
	calls = {}
	calls.update(x86_TI)
	calls.update(mips_TI)
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		re = [v for v in calls if opcode in v]
		if len(re) > 0:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calCompareIns(bl):
	cmps = [
    'cmp', 'cmpeqps', 'cmpeqsd', 'cmpeqss', 'cmpleps',
    'cmplesd', 'cmpltpd', 'cmpltps', 'cmpltsd', 'cmpneqpd',
    'cmpneqps', 'cmpnlepd', 'cmpnlesd', 'cmpps', 'cmps',
    'cmpsb', 'cmpsd', 'cmpsw', 'cmpxchg', 'comisd',
    'comiss',
    'cmpeqpd', 'cmpltss', 'cmpnleps', 'cmpnless',
    'cmpnltpd', 'cmpnltps', 'cmpnltsd', 'cmpnltss',
    'cmpunordpd', 'cmpunordps',
    'fcom', 'fcomi', 'fcomip', 'fcomp', 'fcompp', 'ficom', 'ficomp',
    'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp',
    'pcmpeqb', 'pcmpeqd', 'pcmpeqw', 'pcmpgtb',
    'pcmpgtd', 'pcmpgtw', 'pfcmpeq', 'pfcmpge', 'pfcmpgt',
    'ucomisd', 'ucomiss',
    'vpcmpeqb', 'vpcmpeqd',
    'vpcmpeqw', 'vpcmpgtb', 'vpcmpgtd', 'vpcmpgtw', 'vucomiss',
    'vcmpsd', 'vcomiss', 'vucomisd',
	]
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in cmps:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calMovIns(bl):
	movs = [
    'cmova', 'cmovb', 'cmovbe', 'cmovg', 'cmovge',
    'cmovl', 'cmovle', 'cmovnb', 'cmovno', 'cmovnp',
    'cmovns', 'cmovnz', 'cmovo', 'cmovp', 'cmovs', 'cmovz',
    'fcmovb', 'fcmovbe', 'fcmove', 'fcmovnb',
    'fcmovnbe', 'fcmovne', 'fcmovnu', 'fcmovu',
    'mov', 'movapd', 'movaps', 'movd', 'movdqa', 'movdqu',
    'movhlps', 'movhpd', 'movhps', 'movlhps', 'movlpd',
    'movlps', 'movmskpd', 'movmskps', 'movntdq', 'movnti',
    'movntps', 'movntq', 'movq', 'movs', 'movsb', 'movsd',
    'movss', 'movsw', 'movsx', 'movups', 'movzx',
    'movntpd', 'movupd',
    'pmovmskb', 'pmovzxbd', 'pmovzxwd',
    'vmovapd', 'vmovaps', 'vmovd',
    'vmovddup', 'vmovdqa', 'vmovdqu', 'vmovhps', 'vmovlhps',
    'vmovntdq', 'vmovntpd', 'vmovntps', 'vmovntsd',
    'vmovsd', 'vmovsldup', 'vmovss', 'vmovupd', 'vmovups',
    'vmovhlps', 'vmovlps', 'vmovq', 'vmovshdup',
	]
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in movs:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calTerminationIns(bl):
	terminations = [
    'end',
    'iret', 'iretw',
    'retf', 'reti', 'retfw', 'retn', 'retnw',
    'sysexit', 'sysret',
    'xabort',
	]
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in terminations:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)
	return invoke_num

def calDateDefIns(bl):
	datadefs = ['dd', 'db', 'dw', 'dq', 'dt','extrn','unicode']
	start = bl[0]
	end = bl[1]
	invoke_num = 0
	inst_addr = start
	while inst_addr < end:
		opcode = GetMnem(inst_addr)
		if opcode in datadefs:
			invoke_num += 1
		inst_addr = NextHead(inst_addr)

	return invoke_num


def cal_all_attribute(bl):
	datadefs = ['dd', 'db', 'dw', 'dq', 'dt', 'extrn', 'unicode']
	terminations = [
		'end',
		'iret', 'iretw',
		'retf', 'reti', 'retfw', 'retn', 'retnw',
		'sysexit', 'sysret',
		'xabort',
	]
	movs = [
		'cmova', 'cmovb', 'cmovbe', 'cmovg', 'cmovge',
		'cmovl', 'cmovle', 'cmovnb', 'cmovno', 'cmovnp',
		'cmovns', 'cmovnz', 'cmovo', 'cmovp', 'cmovs', 'cmovz',
		'fcmovb', 'fcmovbe', 'fcmove', 'fcmovnb',
		'fcmovnbe', 'fcmovne', 'fcmovnu', 'fcmovu',
		'mov', 'movapd', 'movaps', 'movd', 'movdqa', 'movdqu',
		'movhlps', 'movhpd', 'movhps', 'movlhps', 'movlpd',
		'movlps', 'movmskpd', 'movmskps', 'movntdq', 'movnti',
		'movntps', 'movntq', 'movq', 'movs', 'movsb', 'movsd',
		'movss', 'movsw', 'movsx', 'movups', 'movzx',
		'movntpd', 'movupd',
		'pmovmskb', 'pmovzxbd', 'pmovzxwd',
		'vmovapd', 'vmovaps', 'vmovd',
		'vmovddup', 'vmovdqa', 'vmovdqu', 'vmovhps', 'vmovlhps',
		'vmovntdq', 'vmovntpd', 'vmovntps', 'vmovntsd',
		'vmovsd', 'vmovsldup', 'vmovss', 'vmovupd', 'vmovups',
		'vmovhlps', 'vmovlps', 'vmovq', 'vmovshdup',
	]
	cmps = [
		'cmp', 'cmpeqps', 'cmpeqsd', 'cmpeqss', 'cmpleps',
		'cmplesd', 'cmpltpd', 'cmpltps', 'cmpltsd', 'cmpneqpd',
		'cmpneqps', 'cmpnlepd', 'cmpnlesd', 'cmpps', 'cmps',
		'cmpsb', 'cmpsd', 'cmpsw', 'cmpxchg', 'comisd',
		'comiss',
		'cmpeqpd', 'cmpltss', 'cmpnleps', 'cmpnless',
		'cmpnltpd', 'cmpnltps', 'cmpnltsd', 'cmpnltss',
		'cmpunordpd', 'cmpunordps',
		'fcom', 'fcomi', 'fcomip', 'fcomp', 'fcompp', 'ficom', 'ficomp',
		'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp',
		'pcmpeqb', 'pcmpeqd', 'pcmpeqw', 'pcmpgtb',
		'pcmpgtd', 'pcmpgtw', 'pfcmpeq', 'pfcmpge', 'pfcmpgt',
		'ucomisd', 'ucomiss',
		'vpcmpeqb', 'vpcmpeqd',
		'vpcmpeqw', 'vpcmpgtb', 'vpcmpgtd', 'vpcmpgtw', 'vucomiss',
		'vcmpsd', 'vcomiss', 'vucomisd',
	]
	calls = {'call': 1, 'jal': 1, 'jalr': 1}
	ArithmeticIns_x86_AI = {'add': 1, 'sub': 1, 'div': 1, 'imul': 1, 'idiv': 1, 'mul': 1, 'shl': 1, 'dec': 1, 'inc': 1}
	ArithmeticIns_mips_AI = {'add': 1, 'addu': 1, 'addi': 1, 'addiu': 1, 'mult': 1, 'multu': 1, 'div': 1, 'divu': 1}
	ArithmeticIns_mips_x86 = {}
	ArithmeticIns_mips_x86.update(ArithmeticIns_x86_AI)
	ArithmeticIns_mips_x86.update(ArithmeticIns_mips_AI)

	LogicInstructions_x86_LI = {'and': 1, 'andn': 1, 'andnpd': 1, 'andpd': 1, 'andps': 1, 'andnps': 1, 'test': 1, 'xor': 1, 'xorpd': 1, 'pslld': 1}
	LogicInstructions_mips_LI = {'and': 1, 'andi': 1, 'or': 1, 'ori': 1, 'xor': 1, 'nor': 1, 'slt': 1, 'slti': 1, 'sltu': 1}
	LogicInstructions_x86_mips = {}
	LogicInstructions_x86_mips.update(LogicInstructions_x86_LI)
	LogicInstructions_x86_mips.update(LogicInstructions_mips_LI)

	TransferIns_x86_TI = {
		'jmp': 1, 'jz': 1, 'jnz': 1, 'js': 1, 'je': 1, 'jne': 1, 'jg': 1, 'jle': 1, 'jge': 1, 'ja': 1, 'jnc': 1,
		'jb': 1,
		'jl': 1, 'jnb': 1, 'jno': 1, 'jnp': 1, 'jns': 1,
		'jo': 1, 'jp': 1,
		'loop': 1, 'loope': 1, 'loopne': 1, 'loopw': 1,
		'loopwe': 1, 'loopwne': 1,
	}
	TransferIns_mips_TI = {'beq': 1, 'bne': 1, 'bgtz': 1, "bltz": 1, "bgez": 1, "blez": 1, 'j': 1, 'jal': 1, 'jr': 1, 'jalr': 1}
	TransferIns_x86_mips = {}
	TransferIns_x86_mips.update(TransferIns_x86_TI)
	TransferIns_x86_mips.update(TransferIns_mips_TI)

	start = bl[0]
	end = bl[1]
	DateDefInsNum = 0
	TerminationInsNum = 0
	MovInsNum = 0
	CompareInsNum = 0
	CallsNum = 0
	InstsNum = 0
	ArithmeticInsNum = 0
	LogicInstructionsNum = 0
	TransferInsNum = 0
	inst_addr = start
	if __MODIFY__:
		Opcodes = []
	while inst_addr < end:
		opcode = GetMnem(inst_addr)

		if __MODIFY__:
			Opcodes.append(opcode)

		re = [v for v in TransferIns_x86_mips if opcode in v]
		if len(re) > 0:
			TransferInsNum += 1
		if opcode in datadefs:
			DateDefInsNum += 1
		if opcode in terminations:
			TerminationInsNum += 1
		if opcode in movs:
			MovInsNum += 1
		if opcode in cmps:
			CompareInsNum += 1
		if opcode in ArithmeticIns_mips_x86:
			ArithmeticInsNum += 1
		if opcode in LogicInstructions_x86_mips:
			LogicInstructionsNum += 1
		InstsNum += 1
		if opcode in calls:
			CallsNum += 1
			if config.Acfg.get_half_data:
				instructions = GetDisasm(inst_addr)
				next_opcode = GetMnem(NextHead(inst_addr))
				if instructions.strip().split(' ')[-1].startswith('sub_') and (next_opcode not in terminations):
					next_ins_addr = NextHead(inst_addr)
					current_ins_length = next_ins_addr - inst_addr
					addr_to_be_called = instructions.strip().split(' ')[-1][4:]
					callsAttribute = str(current_ins_length) + '_' + str(CallsNum) + '_' + str(inst_addr) + '_' + '0x' +str(addr_to_be_called)
					return TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, callsAttribute, ArithmeticInsNum, LogicInstructionsNum, InstsNum
		inst_addr = NextHead(inst_addr)
	if __MODIFY__:
		return TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, CallsNum, ArithmeticInsNum, LogicInstructionsNum, InstsNum, Opcodes	
	return TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, CallsNum, ArithmeticInsNum, LogicInstructionsNum, InstsNum
