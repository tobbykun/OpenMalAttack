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
import multiprocessing
from multiprocessing import Pool, Lock
from dataset import malware_train, malware_test

IDA_PATH = "XXX/idaq64"
SCRIPT_PATH = "scripts/graph_handle_acfg.py"
tmp_sample_root = "dataset/tmp"
TIMEOUT = 90

# ls_than_3000Blocks = []
# lg_than_3000Blocks = []
# error_sample = []
# timeout_sample = []

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

ls_than_3000Blocks = multiprocessing.Manager().list()
lg_than_3000Blocks = multiprocessing.Manager().list()

def pre(malware_dataset):
    print(os.getpid(), len(malware_dataset))
    for i, mPath in enumerate(malware_dataset):
        eventlet.monkey_patch()
        try:
            # mutex.acquire()
            print(i, mPath)
            # mutex.release()

            bytez = Path(mPath).read_bytes()
            data_hash = os.path.basename(mPath)

            with eventlet.Timeout(TIMEOUT):
                tmp_sample_path = osp.join(tmp_sample_root, data_hash)
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
            # timeout_sample.append(str(mPath))

        except Exception as e:
            print(f"[Error]: {e}")
    
    # print('Num of bengin(BlockNum <= 3000): ', len(ls_than_3000Blocks))
    # print('Num of bengin(BlockNum > 3000): ', len(lg_than_3000Blocks))
    # print('Num of Broken bengin: ', len(error_sample))
    # print('Num of Time out:', len(timeout_sample))

# if __name__ == '__main__':
import numpy as np
malware_dataset = np.array_split(np.array(malware_train + malware_test), 10)

# global lock_1 = multiprocessing.Lock()
# global lock_2 = multiprocessing.Lock()

cpu_worker_num = 10
with Pool(cpu_worker_num) as p:
    outputs = p.map(pre, malware_dataset)
    p.close()
    p.join()
# print(output)
# with open(malware_block_num_less_than_3000, 'w') as f:
#     json.dump(output, f)

print('Num of bengin(BlockNum <= 3000): ', len(ls_than_3000Blocks))
print('Num of bengin(BlockNum > 3000): ', len(lg_than_3000Blocks))

malware_le_3000Blocks_dict = {'ls_than_3000_Blocks':list(set(ls_than_3000Blocks)), 'lg_than_3000_Blocks':list(set(lg_than_3000Blocks))}
with open("configs/malware_for_srl.json", 'w') as f:
    json.dump(malware_le_3000Blocks_dict, f)
