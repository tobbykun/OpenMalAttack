#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ************************************
# @Time     : 2021/4/9 0:39
# @Author   : Xiang Ling
# @File     : ModelPredForAttack.py
# @Lab      : nesa.zju.edu.cn
# ************************************

from datetime import datetime

import torch
import torch.utils.data
import torch.utils.data.distributed

from classifiers.malgraph.HierarchicalGraphModel import HierarchicalGraphNeuralNetwork
from utils.malgraph.ParameterClasses import ModelParams
from utils.malgraph.RealBatch import create_real_batch_data
from tqdm import tqdm
import jsonlines
from torch_geometric.data import Data
from utils.malgraph.Vocabulary import Vocab
from torch_geometric.data.batch import Batch



def validate(local_device, one_batch_data, model):
    
    model.eval()
    n_samples = torch.tensor(0, dtype=torch.int).to(local_device)
    
    
    with torch.no_grad():
        # for idx_batch, data in enumerate(tqdm(valid_loader)):
        _real_batch, _position, _hash, _external_list, _function_edges, _true_classes = create_real_batch_data(one_batch=one_batch_data)
        if _real_batch is None:
            raise Exception("Warning: _real_batch is None in creating the real batch data of validation... ")
            return None
        _real_batch = _real_batch.to(local_device)
        _position = torch.tensor(_position, dtype=torch.long).to(local_device)
        _true_classes = _true_classes.float().to(local_device)
        # $
        # _external_list = torch.tensor(_external_list).to(local_device)
        # _function_edges = torch.tensor(_function_edges).to(local_device)
        # $
        batch_pred = model(real_local_batch=_real_batch, real_bt_positions=_position, bt_external_names=_external_list, bt_all_function_edges=_function_edges, local_device=local_device)
        batch_pred = batch_pred.squeeze(-1).detach().cpu()
        
        n_samples += len(batch_pred)
        
    
    return batch_pred



def process_one_item(item, vocab, label=1):
    item_hash = item['hash']
    acfg_list = []
    for one_acfg in item['acfg_list']:  # list of dict of acfg
        block_features = one_acfg['block_features']
        block_edges = one_acfg['block_edges']
        one_acfg_data = Data(x=torch.tensor(block_features, dtype=torch.float), edge_index=torch.tensor(block_edges, dtype=torch.long))
        acfg_list.append(one_acfg_data)

    item_function_names = item['function_names']
    item_function_edges = item['function_edges']

    local_function_name_list = item_function_names[:len(acfg_list)]
    assert len(acfg_list) == len(local_function_name_list), "The length of ACFG_List should be equal to the length of Local_Function_List"
    external_function_name_list = item_function_names[len(acfg_list):]
    external_function_index_list = [vocab[f_name] for f_name in external_function_name_list]
    
    data_pt = Data(hash=item_hash, local_acfgs=acfg_list, external_list=external_function_index_list, function_edges=item_function_edges, targets=label)
    
    return data_pt