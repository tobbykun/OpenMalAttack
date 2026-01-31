import torch
import numpy as np
import networkx as nx
import os
import omegaconf
import glob
import json
import jsonlines
import os.path as osp
from pathlib import Path
from torch_geometric.data import Data
import copy
import pandas as pd
import subprocess

IDA_PATH = "XXX/idaq64"
SCRIPT_PATH = "../scripts/graph_handle_acfg.py"
tmp_sample_root = "../dataset/tmp"

class observation(object):
    def __init__(self, num_node, num_edge, node_feats, feat_num, degs, node_adj):
        assert not pd.isnull(node_feats.numpy()).any()
        assert not pd.isnull(degs.numpy()).any()
        assert not pd.isnull(node_adj.numpy()).any()
        self.node_feats = copy.deepcopy(node_feats)
        self.num_node = num_node
        self.num_edge = num_edge
        self.feat_num = feat_num
        self.degs = degs
        self.node_adj = node_adj
    
    def update_feat(self, node_feats):
        self.node_feats = copy.deepcopy(node_feats)

class FeatsExtractor(object):
    def __init__(self):
        self.sha256 = None
        with open("../configs/OpCodeEncode.json") as f:
            self.OpCodeEncode = json.load(f)
        self.ReverseEncode = {v:k for k,v in self.OpCodeEncode.items()}
        self.feat_num = len(self.OpCodeEncode)
        self.num_node = 0
        self.num_edge = 0
        self.Inst_set()
        self.total_Insts = 0

    def unpack_acfg_list(self, acfg_list):
        self.node_feats = torch.zeros((self.num_node, self.feat_num)).float()   # BUG: torch.FloatTensor() 不会初始化元素为0
        self.degs = torch.zeros(self.num_node)
        x = []
        start_edges = []
        end_edges = []
        start_index = 0
        label=1
        cnt = 0
        for item in acfg_list:
            x += [it[:-1] for it in item['block_features']]
            tmp = [it[-1] for it in item['block_features']]
            self.total_Insts += sum([len(it[-1]) for it in item['block_features']])
            for insts in tmp:
                for ins in insts:
                    if ins in self.OpCodeEncode.keys():
                        self.node_feats[cnt][self.OpCodeEncode[ins]] += 1
                cnt += 1

            start_edges += [x + start_index for x in item['block_edges'][0]]
            end_edges += [x + start_index for x in item['block_edges'][1]]
            start_index += item['block_number']
        x = np.array(x).astype(np.float64)
        edge_index = np.array([start_edges, end_edges]).astype(np.int64)
        self.num_edge = len(edge_index[0])
        for i in range(len(edge_index[0])):
            self.degs[edge_index[0][i]] += 1
        return x, torch.from_numpy(edge_index)


    def handle_acfg(self, tmp_sample_path):
        cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + tmp_sample_path
        p = subprocess.Popen(cmd, shell=True)
        p.wait()

    def cnt_all_op(self, node_feat):
        DateDefInsNum = 0
        TerminationInsNum = 0
        MovInsNum = 0
        CompareInsNum = 0
        CallsNum = 0
        InstsNum = 0
        ArithmeticInsNum = 0
        LogicInstructionsNum = 0
        TransferInsNum = 0
        Opcodes = []
        for i, opcd_idx in enumerate(node_feat):
            opcode = self.ReverseEncode[i]
            if opcd_idx != 0:
                Opcodes.append(opcode)
            else:
                continue
            # re = [v for v in self.TransferIns_x86_mips if opcode in v]
            # if len(re) > 0:
            if opcode in self.TransferIns_x86_mips:
                TransferInsNum += opcd_idx
            if opcode in self.datadefs:
                DateDefInsNum += opcd_idx
            if opcode in self.terminations:
                TerminationInsNum += opcd_idx
            if opcode in self.movs:
                MovInsNum += opcd_idx
            if opcode in self.cmps:
                CompareInsNum += opcd_idx
            if opcode in self.ArithmeticIns_mips_x86:
                ArithmeticInsNum += opcd_idx
            if opcode in self.LogicInstructions_x86_mips:
                LogicInstructionsNum += opcd_idx
            InstsNum += opcd_idx
            if opcode in self.calls:
                CallsNum += opcd_idx

        res = [ArithmeticInsNum, 
               CallsNum, 
               InstsNum, 
               LogicInstructionsNum, 
               TransferInsNum, 
               CompareInsNum, 
               MovInsNum, 
               TerminationInsNum, 
               DateDefInsNum, 
               Opcodes]
        return res

    def get_graph(self):
        # 将acfg_list提取成图的形式
        x = []
        start_edges = []
        end_edges = []
        start_index = 0
        label=1
        for item in self.acfg_list:
            x += [it[:-1] for it in item['block_features']]
            start_edges += [x + start_index for x in item['block_edges'][0]]
            end_edges += [x + start_index for x in item['block_edges'][1]]
            start_index += item['block_number']

        x = torch.tensor(x, dtype=torch.float32)
        edge_index = torch.tensor([start_edges, end_edges], dtype=torch.int64)
        y = torch.tensor([label], dtype=torch.int64)
        graph = Data(x=x, edge_index=edge_index, y=y)
        return graph

    def get_acfg_list(self):
        return self.acfg_list

    def get_data_item(self):
        return self.data_item

    def raw_features(self):
        tmp_sample_path = osp.join(tmp_sample_root, self.sha256)
        if not os.path.exists(tmp_sample_path+".json"):
            if not os.path.exists(tmp_sample_path):
                with open(tmp_sample_path, 'wb') as out:
                    out.write(bytez)

            self.handle_acfg(tmp_sample_path)

        with open(tmp_sample_path+".json", "r", encoding="utf-8") as file:
            data_item = jsonlines.Reader(file).read()
        
        self.data_item = data_item
        
        self.acfg_list = copy.deepcopy(data_item['acfg_list'])
# ! no padding
        self.num_node = 0
        for item in self.acfg_list:
            self.num_node += item['block_number']
# ! no padding
        # x：特征   edge_index：[起点，终点]    y：标签
        
        _, self.node_adj = self.unpack_acfg_list(self.acfg_list)    # x, edge_index
    
    def get_features(self):
        return self.OpCodeEncode, self.node_feats

    def get_node_adj(self):
        return self.node_adj

    def feature_extr(self, sha256):
        if self.sha256 == sha256:
            return observation(self.num_node, self.num_edge, self.node_feats, self.feat_num, self.degs, self.node_adj)
        else:
            self.sha256 = sha256
            self.raw_features()
            return observation(self.num_node, self.num_edge, self.node_feats, self.feat_num, self.degs, self.node_adj)
                
    def update_feats(self, nodes_feats):
        assert nodes_feats is not None
        idx = 0
        for i in range(len(self.acfg_list)):
            for j in range(len(self.acfg_list[i]['block_features'])):
                self.acfg_list[i]['block_features'][j][2:] = self.cnt_all_op(nodes_feats[idx])
                idx += 1
        self.node_feats = nodes_feats
        self.data_item['acfg_list'] = copy.deepcopy(self.acfg_list)


    def Inst_set(self):
        self.datadefs = ['dd', 'db', 'dw', 'dq', 'dt', 'extrn', 'unicode']
        self.terminations = [
            'end',
            'iret', 'iretw',
            'retf', 'reti', 'retfw', 'retn', 'retnw',
            'sysexit', 'sysret',
            'xabort',
        ]
        self.movs = [
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
        self.cmps = [
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
        self.calls = {'call': 1, 'jal': 1, 'jalr': 1}
        ArithmeticIns_x86_AI = {'add': 1, 'sub': 1, 'div': 1, 'imul': 1, 'idiv': 1, 'mul': 1, 'shl': 1, 'dec': 1, 'inc': 1}
        ArithmeticIns_mips_AI = {'add': 1, 'addu': 1, 'addi': 1, 'addiu': 1, 'mult': 1, 'multu': 1, 'div': 1, 'divu': 1}
        self.ArithmeticIns_mips_x86 = {}
        self.ArithmeticIns_mips_x86.update(ArithmeticIns_x86_AI)
        self.ArithmeticIns_mips_x86.update(ArithmeticIns_mips_AI)

        LogicInstructions_x86_LI = {'and': 1, 'andn': 1, 'andnpd': 1, 'andpd': 1, 'andps': 1, 'andnps': 1, 'test': 1, 'xor': 1, 'xorpd': 1, 'pslld': 1}
        LogicInstructions_mips_LI = {'and': 1, 'andi': 1, 'or': 1, 'ori': 1, 'xor': 1, 'nor': 1, 'slt': 1, 'slti': 1, 'sltu': 1}
        self.LogicInstructions_x86_mips = {}
        self.LogicInstructions_x86_mips.update(LogicInstructions_x86_LI)
        self.LogicInstructions_x86_mips.update(LogicInstructions_mips_LI)

        TransferIns_x86_TI = {
            'jmp': 1, 'jz': 1, 'jnz': 1, 'js': 1, 'je': 1, 'jne': 1, 'jg': 1, 'jle': 1, 'jge': 1, 'ja': 1, 'jnc': 1,
            'jb': 1,
            'jl': 1, 'jnb': 1, 'jno': 1, 'jnp': 1, 'jns': 1,
            'jo': 1, 'jp': 1,
            'loop': 1, 'loope': 1, 'loopne': 1, 'loopw': 1,
            'loopwe': 1, 'loopwne': 1,
        }
        TransferIns_mips_TI = {'beq': 1, 'bne': 1, 'bgtz': 1, "bltz": 1, "bgez": 1, "blez": 1, 'j': 1, 'jal': 1, 'jr': 1, 'jalr': 1}
        self.TransferIns_x86_mips = {}
        self.TransferIns_x86_mips.update(TransferIns_x86_TI)
        self.TransferIns_x86_mips.update(TransferIns_mips_TI)

