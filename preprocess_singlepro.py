from dataclasses import dataclass
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import functional
from torch_geometric.nn import GCNConv, SAGEConv, Linear
from torch_geometric.nn import global_mean_pool, global_max_pool
from torch_geometric.data import Batch
import requests
import omegaconf
import glob
import jsonlines
import json
import subprocess
from torch_geometric.data import Data
import os
import os.path as osp
from os import PathLike
from pathlib import Path
from torch.utils.data import Dataset

import time
import eventlet
import random
from dataset import malware_data, malware_train, malware_test

IDA_PATH = "XXX/idaq64"
SCRIPT_PATH = "scripts/graph_handle_acfg.py"
tmp_sample_root = "dataset/tmp"
TIMEOUT = 90

class PEDataset(Dataset):
    def __init__(self, root: PathLike, filt=None):
        '''basic PE dataset

        Args:
            root (str): root abspath of dataset
        '''
        self.root = root
        filt = filt or (lambda x: '.' not in x)
        self.paths = list(Path(root).rglob("*"))
        self.paths = [p for p in self.paths if filt(p.name) and p.is_file()]

    def __getitem__(self, index):
        return self.paths[index]

    def __len__(self):
        return len(self.paths)

def count_insts_and_blockNum(acfg_list):
    # 将acfg_list提取成图的形式
    Insts = []
    BlockNum = 0
    for item in acfg_list:
        for it in item['block_features']:
            Insts += it[-1]
        BlockNum += item['block_number']
    return Insts, BlockNum

def handle_acfg(tmp_sample_path):
    cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + tmp_sample_path
    p = subprocess.Popen(cmd, shell=True)
    p.wait()

def pre(malware_dataset):
    ls_than_3000Blocks = []
    lg_than_3000Blocks = []
    error_sample = []
    timeout_sample = []
    for i, mPath in enumerate(malware_dataset):
        if i >= 32000:
            break
        eventlet.monkey_patch()
        try:

            bytez = Path(mPath).read_bytes()
            data_hash = os.path.basename(mPath)

            with eventlet.Timeout(TIMEOUT):
                tmp_sample_path = osp.join(tmp_sample_root, data_hash)
                print(i, tmp_sample_path)
                if not os.path.exists(tmp_sample_path+".json"):
                    if not os.path.exists(tmp_sample_path):
                        with open(tmp_sample_path, 'wb') as out:
                            out.write(bytez)
                    handle_acfg(tmp_sample_path)

            with open(tmp_sample_path+".json", "r+", encoding="utf-8") as file:
                data_item = jsonlines.Reader(file).read()

            acfg_list = data_item['acfg_list']
            Insts, BlockNum = count_insts_and_blockNum(acfg_list)

            if BlockNum <= 3000:
                ls_than_3000Blocks.append(str(mPath))
            else:
                lg_than_3000Blocks.append(str(mPath))
        
        except eventlet.timeout.Timeout:
            print(f"timeout: {mPath}")
            os.system("kill $(ps -aux | grep idaq64 | awk '{print $2}')")
            os.system(f"rm {tmp_sample_path}*")
            os.system(f"rm {mPath}*")
            timeout_sample.append(str(mPath))

        except Exception as e:
            print(e)
            if any([name.endswith(('.dmp')) for name in os.listdir("/tmp/ida/")]):
                os.system("rm /tmp/ida/*")
            error_sample.append(str(mPath))
    
    print('Num of malware(BlockNum <= 3000): ', len(ls_than_3000Blocks))
    print('Num of malware(BlockNum > 3000): ', len(lg_than_3000Blocks))
    print('Num of Broken malware: ', len(error_sample))
    print('Num of Time out:', len(timeout_sample))
    

    malware_le_3000Blocks_dict = {'ls_than_3000_Blocks':list(set(ls_than_3000Blocks)), 'lg_than_3000_Blocks':list(set(lg_than_3000Blocks)), 'error_sample': list(set(error_sample)), 'timeout': list(set(timeout_sample))}
    with open("configs/malware_preprocessed_train.json", 'w') as f:
        json.dump(malware_le_3000Blocks_dict, f)

if __name__ == '__main__':
    pre(malware_train)
