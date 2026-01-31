# coding:utf-8

import copy
import networkx as nx
from idautils import *
import idaapi
from idc import *
from graph_analysis_ida import *
import jsonlines

__MODIFY__ = True

def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

def getCfg(func, externs_eas, ea_externs):
    func_start = func.startEA
    func_end = func.endEA
    
    cfg = nx.DiGraph()  # 初始化cfg
    control_blocks = obtain_block_sequence(func)  # 得到cfg中的块
    
    # i = 0
    visited = {}
    # start_node = None
    for bl in control_blocks:
        start = control_blocks[bl][0]
        end = control_blocks[bl][1]
        src_node = (start, end)
        if src_node not in visited:
            src_id = len(cfg)
            visited[src_node] = src_id
            cfg.add_node(src_id)
            cfg.node[src_id]['label'] = src_node
        else:
            src_id = visited[src_node]

        # if end in seq_blocks and GetMnem(PrevHead(end)) != 'jmp':
        if start == func_start:
            cfg.node[src_id]['c'] = "start"
            # start_node = src_node
        if end == func_end:
            cfg.node[src_id]['c'] = "end"

        refs = CodeRefsTo(start, 0)  # 统计跳转Flow
        for ref in refs:
            if ref in control_blocks:
                dst_node = control_blocks[ref]
                if dst_node not in visited:
                    visited[dst_node] = len(cfg)
                dst_id = visited[dst_node]
                cfg.add_edge(dst_id, src_id)
                cfg.node[dst_id]['label'] = dst_node

        refs = CodeRefsTo(start, 1)  # 除了跳转Flow，将正常FLOW也算上
        for ref in refs:
            if ref in control_blocks:
                dst_node = control_blocks[ref]
                if dst_node not in visited:
                    visited[dst_node] = len(cfg)
                dst_id = visited[dst_node]
                cfg.add_edge(dst_id, src_id)
                cfg.node[dst_id]['label'] = dst_node

    cfg = attributingRe(cfg, externs_eas, ea_externs)
    return cfg


def attributingRe(cfg, externs_eas, ea_externs):
    """
    为每个基本块生成自定义的属性
    """
    for node_id in cfg:
        bl = cfg.node[node_id]['label']

        if __MODIFY__:
            TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, CallsNum, ArithmeticInsNum, LogicInstructionsNum, InstsNum, Opcodes = cal_all_attribute(bl)
        else:
            TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, CallsNum, ArithmeticInsNum, LogicInstructionsNum, InstsNum = cal_all_attribute(bl)

        # numIns = calInsts(bl)  # No. of Instruction
        cfg.node[node_id]['numIns'] = InstsNum

        # numCalls = calCalls(bl)  # No. of Calls
        cfg.node[node_id]['numCalls'] = CallsNum

        # numLIs = calLogicInstructions(bl)  # 这个不再Genius的范围内
        cfg.node[node_id]['numLIs'] = LogicInstructionsNum

        # numAs = calArithmeticIns(bl)  # No. of Arithmetic Instructions
        cfg.node[node_id]['numAs'] = ArithmeticInsNum

        strings, consts = getBBconsts(bl)  # String and numeric constants
        # write_data_to_filename('/home/wzy/get_test_dataset_acfg/debug.log', str([bl,ArithmeticInsNum]))
        cfg.node[node_id]['numNc'] = len(strings) + len(consts)
        cfg.node[node_id]['consts'] = consts
        cfg.node[node_id]['strings'] = strings

        # externs = retrieveExterns(bl, ea_externs)  # 外部函数，PE文件统计为0
        # cfg.node[node_id]['externs'] = externs

        # numTIs = calTransferIns(bl)  # No. of Transfer Instruction
        cfg.node[node_id]['numTIs'] = TransferInsNum

        # numCmpIs = calCompareIns(bl)  # No. of Compare Instructions
        cfg.node[node_id]['numCmpIs'] = CompareInsNum

        # numMovIs = calMovIns(bl)  # No. of Mov Instructions
        cfg.node[node_id]['numMovIs'] = MovInsNum

        # numTermIs = calTerminationIns(bl)  # No. of Termination Instructions
        cfg.node[node_id]['numTermIs'] = TerminationInsNum

        # numDefIs = calDateDefIns(bl)  # No. of Date Declaration Instructions
        cfg.node[node_id]['numDefIs'] = DateDefInsNum
    
        if __MODIFY__:
            cfg.node[node_id]['Opcodes'] = Opcodes
    return cfg


def obtain_block_sequence(func):
    control_blocks = {}
    blocks = [(v.startEA, v.endEA) for v in idaapi.FlowChart(func)]  # 返回该函数所有的basicblock
    for bl in blocks:  # delete wrong blocks
        base = bl[0]
        if (func.startEA <= base <= func.endEA) or SegName(base).count('htext') > 0:
            control_ea = checkCB(bl)
            control_blocks[control_ea] = bl
    return control_blocks

def checkCB(bl):  # 检查基本块的正确性
    start = bl[0]
    end = bl[1]
    ea = start
    while ea < end:
        if checkCondition(ea):
            return ea
        ea = NextHead(ea)
    return PrevHead(end)


def checkCondition(ea):  # 检查是否是跳转指令
    mips_branch = {"beqz": 1, "beq": 1, "bne": 1, "bgez": 1, "b": 1, "bnez": 1, "bgtz": 1, "bltz": 1, "blez": 1,
                   "bgt": 1, "bge": 1, "blt": 1, "ble": 1, "bgtu": 1, "bgeu": 1, "bltu": 1, "bleu": 1}
    x86_branch = {"jz": 1, "jnb": 1, "jne": 1, "je": 1, "jg": 1, "jle": 1, "jl": 1, "jge": 1, "ja": 1, "jae": 1,
                  "jb": 1, "jbe": 1, "jo": 1, "jno": 1, "js": 1, "jns": 1, "jmp": 1, "jnz": 1}
    arm_branch = {"B": 1, "BAL": 1, "BNE": 1, "BEQ": 1, "BPL": 1, "BMI": 1, "BCC": 1, "BLO": 1, "BCS": 1, "BHS": 1,
                  "BVC": 1, "BVS": 1, "BGT": 1, "BGE": 1, "BLT": 1, "BLE": 1, "BHI": 1, "BLS": 1}
    conds = {}  # 只检查mips和x86，不检查arm跳转指令
    conds.update(mips_branch)  # 检查mips跳转指令
    conds.update(x86_branch)  # 检查x86跳转指令
    opcode = GetMnem(ea)
    if opcode in conds:
        return True
    return False
