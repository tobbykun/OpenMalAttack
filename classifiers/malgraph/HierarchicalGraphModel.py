import logging
import sys

import torch
from torch import nn
from torch.nn import Linear
from torch.nn import Sequential
from torch.nn import functional as pt_f
from torch_geometric.data import Batch, Data
from torch_geometric.nn.conv import GCNConv, SAGEConv, GATConv, GINConv
from torch_geometric.nn.glob import global_max_pool, global_mean_pool, GlobalAttention

sys.path.append("..")
from utils.malgraph.ParameterClasses import ModelParams
from utils.malgraph.Vocabulary import Vocab


def div_with_small_value(n, d, eps=1e-8):
    d = d * (d > eps).float() + eps * (d <= eps).float()
    return n / d


def padding_tensors(tensor_list):
    num = len(tensor_list)
    max_len = max([s.shape[0] for s in tensor_list])
    out_dims = (num, max_len, *tensor_list[0].shape[1:])
    out_tensor = tensor_list[0].data.new(*out_dims).fill_(0)
    mask = tensor_list[0].data.new(*out_dims).fill_(0)
    for i, tensor in enumerate(tensor_list):
        length = tensor.size(0)
        out_tensor[i, :length] = tensor
        mask[i, :length] = 1
    return out_tensor, mask


def inverse_padding_tensors(tensors, masks):
    mask_index = torch.sum(masks, dim=-1) / masks.size(-1)
    
    _out_mask_select = torch.masked_select(tensors, (masks == 1)).view(-1, tensors.size(-1))
    
    batch_index = torch.sum(mask_index, dim=-1)
    
    batch_idx_list = []
    for idx, num in enumerate(batch_index):
        batch_idx_list.extend([idx for _ in range(int(num))])
    return _out_mask_select, batch_idx_list


class HierarchicalGraphNeuralNetwork(nn.Module):
    def __init__(self, model_params: ModelParams, external_vocab: Vocab, global_log: logging.Logger):  # device=torch.device('cuda')
        super(HierarchicalGraphNeuralNetwork, self).__init__()
        
        self.conv = model_params.gnn_type.lower()
        if self.conv not in ['gcn', 'gat', 'graphsage', 'gin']:
            raise NotImplementedError
        self.pool = model_params.pool_type.lower()
        if self.pool not in ["global_max_pool", "global_mean_pool", "global_gated_attention"]:
            raise NotImplementedError
        
        # self.device = device
        self.global_log = global_log
        
        # Hierarchical 1: Control Flow Graph (CFG) embedding and pooling
        if type(model_params.cfg_filters) == str:
            cfg_filter_list = [int(number_filter) for number_filter in model_params.cfg_filters.split("-")]
        else:
            cfg_filter_list = [int(model_params.cfg_filters)]
        cfg_filter_list.insert(0, model_params.acfg_init_dims)
        self.cfg_filter_length = len(cfg_filter_list)
        
        # GCN for cfg
        cfg_gcn_params = [dict(in_channels=cfg_filter_list[i], out_channels=cfg_filter_list[i + 1], cached=False, bias=True) for i in range(self.cfg_filter_length - 1)]
        # GraphSAGE for cfg
        cfg_graphsage_params = [dict(in_channels=cfg_filter_list[i], out_channels=cfg_filter_list[i + 1], bias=True) for i in range(self.cfg_filter_length - 1)]
        # GAT for cfg
        cfg_gat_params = [dict(in_channels=cfg_filter_list[i], out_channels=cfg_filter_list[i + 1], heads=4, concat=False, bias=True) for i in range(self.cfg_filter_length - 1)]
        # GIN for cfg
        cfg_gin_params = [dict(nn=nn.Linear(in_features=cfg_filter_list[i], out_features=cfg_filter_list[i + 1])) for i in range(self.cfg_filter_length - 1)]
        
        cfg_conv_layer_constructor = {
            'gcn': dict(constructor=GCNConv, kwargs=cfg_gcn_params),
            'gat': dict(constructor=GATConv, kwargs=cfg_gat_params),
            'graphsage': dict(constructor=SAGEConv, kwargs=cfg_graphsage_params),
            'gin': dict(constructor=GINConv, kwargs=cfg_gin_params)
        }
        
        cfg_conv = cfg_conv_layer_constructor[self.conv]
        cfg_constructor = cfg_conv['constructor']
        for i in range(self.cfg_filter_length - 1):
            setattr(self, 'CFG_gnn_{}'.format(i + 1), cfg_constructor(**cfg_conv['kwargs'][i]))
        
        # self.dropout = nn.Dropout(p=model_params.dropout_rate).to(self.device)
        self.dropout = nn.Dropout(p=model_params.dropout_rate)
        
        # Hierarchical 2: Function Call Graph (FCG) embedding and pooling
        self.external_embedding_layer = nn.Embedding(num_embeddings=external_vocab.max_vocab_size + 2, embedding_dim=cfg_filter_list[-1], padding_idx=external_vocab.pad_idx)
        # print(type(model_params.fcg_filters), model_params.fcg_filters)
        if type(model_params.fcg_filters) == str:
            fcg_filter_list = [int(number_filter) for number_filter in model_params.fcg_filters.split("-")]
        else:
            fcg_filter_list = [int(model_params.fcg_filters)]
        
        fcg_filter_list.insert(0, cfg_filter_list[-1])
        self.fcg_filter_length = len(fcg_filter_list)
        
        # GCN for fcg
        fcg_gcn_params = [dict(in_channels=fcg_filter_list[i], out_channels=fcg_filter_list[i + 1], cached=False, bias=True) for i in range(self.fcg_filter_length - 1)]
        # GraphSAGE for fcg
        fcg_graphsage_params = [dict(in_channels=fcg_filter_list[i], out_channels=fcg_filter_list[i + 1], bias=True) for i in range(self.fcg_filter_length - 1)]
        # GAT for cfg
        fcg_gat_params = [dict(in_channels=fcg_filter_list[i], out_channels=fcg_filter_list[i + 1], heads=4, concat=False, bias=True) for i in range(self.fcg_filter_length - 1)]
        # GIN for cfg
        fcg_gin_params = [dict(nn=nn.Linear(in_features=fcg_filter_list[i], out_features=fcg_filter_list[i + 1])) for i in range(self.fcg_filter_length - 1)]
        
        fcg_conv_layer_constructor = {
            'gcn': dict(constructor=GCNConv, kwargs=fcg_gcn_params),
            'gat': dict(constructor=GATConv, kwargs=fcg_gat_params),
            'graphsage': dict(constructor=SAGEConv, kwargs=fcg_graphsage_params),
            'gin': dict(constructor=GINConv, kwargs=fcg_gin_params)
        }
        fcg_conv = fcg_conv_layer_constructor[self.conv]
        fcg_constructor = fcg_conv['constructor']
        for i in range(self.fcg_filter_length - 1):
            setattr(self, 'FCG_gnn_{}'.format(i + 1), fcg_constructor(**fcg_conv['kwargs'][i]))
        
        # global pooling models with necessary models
        if self.pool == "global_gated_attention":
            cfg_channel = cfg_filter_list[-1]
            self.cfg_global_gated_attention = GlobalAttention(gate_nn=Sequential(nn.Linear(cfg_channel, cfg_channel), nn.ReLU(), nn.Linear(cfg_channel, 1)),
                                                              nn=nn.Linear(cfg_channel, cfg_channel))
            fcg_channel = fcg_filter_list[-1]
            self.fcg_global_gated_attention = GlobalAttention(gate_nn=Sequential(nn.Linear(fcg_channel, fcg_channel), nn.ReLU(), nn.Linear(fcg_channel, 1)),
                                                              nn=nn.Linear(fcg_channel, fcg_channel))
        
        # skip concat self-attention multi-heads if necessary
        self.skip_attention_heads = model_params.skip_att_heads
        if self.skip_attention_heads >= 1:
            assert cfg_filter_list[-1] == fcg_filter_list[-1], "cfg_filter_list should be equal to fcg_filter_list"
        
        # Last Projection Function: gradually project with more linear layers
        self.pj1 = Linear(in_features=fcg_filter_list[-1], out_features=int(fcg_filter_list[-1] / 2))
        self.pj2 = Linear(in_features=int(fcg_filter_list[-1] / 2), out_features=int(fcg_filter_list[-1] / 4))
        self.pj3 = Linear(in_features=int(fcg_filter_list[-1] / 4), out_features=1)
        
        self.last_activation = nn.Sigmoid()
        # self.last_activation = nn.Softmax(dim=1)
        # self.last_activation = nn.LogSoftmax(dim=1)
    
    def forward_cfg_gnn(self, local_batch: Batch):
        in_x, edge_index = local_batch.x, local_batch.edge_index
        for i in range(self.cfg_filter_length - 1):
            out_x = getattr(self, 'CFG_gnn_{}'.format(i + 1))(x=in_x, edge_index=edge_index)
            out_x = pt_f.relu(out_x, inplace=True)
            out_x = self.dropout(out_x)
            in_x = out_x
        local_batch.x = in_x
        return local_batch
    
    def aggregate_cfg_batch_pooling(self, local_batch: Batch):
        if self.pool == 'global_max_pool':
            x_pool = global_max_pool(x=local_batch.x, batch=local_batch.batch)
        elif self.pool == 'global_mean_pool':
            x_pool = global_mean_pool(x=local_batch.x, batch=local_batch.batch)
        elif self.pool == "global_gated_attention":
            x_pool = self.cfg_global_gated_attention(x=local_batch.x, batch=local_batch.batch)
        else:
            raise NotImplementedError
        return x_pool
    
    def forward_fcg_gnn(self, function_batch: Batch):
        in_x, edge_index = function_batch.x, function_batch.edge_index
        for i in range(self.fcg_filter_length - 1):
            out_x = getattr(self, 'FCG_gnn_{}'.format(i + 1))(x=in_x, edge_index=edge_index)
            out_x = pt_f.relu(out_x, inplace=True)
            out_x = self.dropout(out_x)
            in_x = out_x
        function_batch.x = in_x
        return function_batch
    
    def aggregate_fcg_batch_pooling(self, function_batch: Batch):
        if self.pool == 'global_max_pool':
            x_pool = global_max_pool(x=function_batch.x, batch=function_batch.batch)
        elif self.pool == 'global_mean_pool':
            x_pool = global_mean_pool(x=function_batch.x, batch=function_batch.batch)
        elif self.pool == "global_gated_attention":
            x_pool = self.fcg_global_gated_attention(x=function_batch.x, batch=function_batch.batch)
        else:
            raise NotImplementedError
        return x_pool
    
    def aggregate_final_skip_pooling(self, x, batch):
        if self.pool == 'global_max_pool':
            x_pool = global_max_pool(x=x, batch=batch)
        elif self.pool == 'global_mean_pool':
            x_pool = global_mean_pool(x=x, batch=batch)
        elif self.pool == "global_gated_attention":
            x_pool = self.fcg_global_gated_attention(x=x, batch=batch)
        else:
            raise NotImplementedError
        return x_pool
    
    @staticmethod
    def cosine_attention(mtx1, mtx2):
        """
        
        :param mtx1: (batch, seq_len1, hidden_size)
        :param mtx2: (batch, seq_len2, hidden_size)
        :return: (batch, seq_len1, seq_len2)
        """
        # (batch, seq_len1, 1)
        v1_norm = mtx1.norm(p=2, dim=2, keepdim=True)
        # (batch, 1, seq_len2)
        v2_norm = mtx2.norm(p=2, dim=2, keepdim=True).permute(0, 2, 1)
        
        # (batch, seq_len1, seq_len2)
        a = torch.bmm(mtx1, mtx2.permute(0, 2, 1))
        d = v1_norm * v2_norm
        
        return div_with_small_value(a, d)
    
    def forward(self, real_local_batch: Batch, real_bt_positions: list, bt_external_names: list, bt_all_function_edges: list, local_device: torch.device):
        
        # step 0: put arguments to self.device
        # real_local_batch = real_local_batch.to(self.device)
        
        # step 1: Hierarchical 1: Control Flow Graph (CFG) embedding and pooling
        
        rtn_local_batch = self.forward_cfg_gnn(local_batch=real_local_batch)
        
        x_cfg_pool = self.aggregate_cfg_batch_pooling(local_batch=rtn_local_batch)
        
        # step 2: build the Function Call Graph (FCG) Data/Batch datasets
        assert len(real_bt_positions) - 1 == len(bt_external_names), "all should be equal to the batch size ... "
        assert len(real_bt_positions) - 1 == len(bt_all_function_edges), "all should be equal to the batch size ... "
        
        fcg_list = []
        fcg_internal_list = []
        for idx_batch in range(len(real_bt_positions) - 1):
            start_pos, end_pos = real_bt_positions[idx_batch: idx_batch + 2]
            # logger.debug("in {}-th batch, start = {}, end = {}".format(idx_batch, start_pos, end_pos))
            
            idx_x_cfg = x_cfg_pool[start_pos: end_pos]
            fcg_internal_list.append(idx_x_cfg)
            
            idx_x_external = self.external_embedding_layer(torch.tensor([bt_external_names[idx_batch]], dtype=torch.long).to(local_device))
            idx_x_external = idx_x_external.squeeze(dim=0)
            
            idx_x_total = torch.cat([idx_x_cfg, idx_x_external], dim=0)
            
            idx_function_edge = torch.tensor(bt_all_function_edges[idx_batch], dtype=torch.long)
            # logger.debug("in {}-th batch, idx_function_edge size = {}".format(idx_batch, idx_function_edge.size()))
            
            idx_graph_data = Data(x=idx_x_total, edge_index=idx_function_edge).to(local_device)
            # logger.debug("in {}-th batch, idx_graph_data = {} ".format(idx_batch, idx_graph_data))
            
            fcg_list.append(idx_graph_data)
        # fcg_batch = Batch.from_data_list(fcg_list).to(self.device)
        fcg_batch = Batch.from_data_list(fcg_list)

        rtn_fcg_batch = self.forward_fcg_gnn(function_batch=fcg_batch)  # [batch_size, max_node_size, dim]

        x_fcg_pool = self.aggregate_fcg_batch_pooling(function_batch=rtn_fcg_batch)  # [batch_size, 1, dim] => [batch_size, dim]
        if self.skip_attention_heads >= 1:
            x_fcg_pool = torch.unsqueeze(x_fcg_pool, 1)  # [batch_size, dim] => [batch_size, 1, dim]
            skip_concat_list = []
            assert len(fcg_internal_list) == x_fcg_pool.size(0), "should be equal ... "
            for a, b in zip(fcg_internal_list, x_fcg_pool):
                skip_concat_list.append(torch.cat([a, b], dim=0))
            
            ret2, mask = padding_tensors(skip_concat_list)
            cosine_sim = self.cosine_attention(ret2, ret2)
            cosine_softmax = pt_f.softmax(cosine_sim, dim=2)
            
            att_weight_x = torch.matmul(cosine_softmax, ret2)
            skip_x_masked, batch_idx_list = inverse_padding_tensors(tensors=att_weight_x, masks=mask)
            
            batch_final = self.aggregate_final_skip_pooling(x=skip_x_masked, batch=torch.tensor(batch_idx_list).to(local_device))
        else:
            batch_final = x_fcg_pool
        
        # step 4: last project to the number_of_numbers (binary)
        bt_final_embed = self.pj3(self.pj2(self.pj1(batch_final)))
        
        bt_pred = self.last_activation(bt_final_embed)
        # print("\nfinal: ", bt_pred.size(), bt_pred)
        # self.global_log.info("end to forward model ...")
        return bt_pred
