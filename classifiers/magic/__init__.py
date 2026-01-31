
from dataclasses import dataclass
from torch_geometric.data import Data
import torch
import requests
import jsonlines
import subprocess
import os.path
import numpy as np
from .model import MagicModel, MagicModelParams

__MODIFY__ = True
__TEST__ = False

@dataclass
class configuration:
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    gnn_type = "GCN"
    pool_type = "global_max_pool"
    acfg_init_dims = 11
    cfg_filters = "128-256-384-256"
    dropout_rate = 0.5
    use_activation = True
    last_activation = "sigmoid"
    model_path = "../../models//magic/best_magic_model.pt"
    IDA_PATH = "The path to the directory containing idaq64."
    SCRIPT_PATH = "../../scripts/graph_handle_acfg.py"
    tmp_sample_root = "../../dataset/tmp"
    threshold_type = '100fpr'

def transform_acfg_list_to_graph(acfg_list):
    # 将acfg_list提取成图的形式
    x = []
    start_edges = []
    end_edges = []
    start_index = 0
    label=1
    for item in acfg_list:
        if __MODIFY__:
            x += [it[:-1] for it in item['block_features']]
        else:
            x += item['block_features']
        start_edges += [x + start_index for x in item['block_edges'][0]]
        end_edges += [x + start_index for x in item['block_edges'][1]]
        start_index += item['block_number']

    if __TEST__:
        x00 = np.array(x).astype(np.int64)
        edge_index00 = np.array([start_edges, end_edges]).astype(np.int64)
        print(x00)
        print(edge_index00)

    x = torch.tensor(x, dtype=torch.float32)
    edge_index = torch.tensor([start_edges, end_edges], dtype=torch.int64)
    y = torch.tensor([label], dtype=torch.int64)
    graph = Data(x=x, edge_index=edge_index, y=y)
    return graph

class MagicClsf():
    def __init__(self, **kwargs):
        self.__name__ = 'Magic'

        self.config = configuration()
        self.config.__dict__.update(kwargs)

        self.threshold_type = self.config.threshold_type
        if self.threshold_type=='100fpr':
            self.clsf_threshold = 0.50642
        elif self.threshold_type=='1000fpr':
            self.clsf_threshold = 0.94783
        else:
            raise NotImplementedError
        
        _model_params = MagicModelParams(device=self.config.device,
                                        gnn_type=self.config.gnn_type,
                                        pool_type=self.config.pool_type,
                                        acfg_init_dims=self.config.acfg_init_dims,
                                        cfg_filters=self.config.cfg_filters,
                                        dropout_rate=self.config.dropout_rate,
                                        use_activation=self.config.use_activation,
                                        last_activation=self.config.last_activation)

        self.model = MagicModel(_model_params)
        self.model.load_state_dict(torch.load(self.config.model_path))
        self.model.to(self.config.device)
        self.model.eval()

    def __call__(self, *args, **kwargs):

        bytez = kwargs['bytez']
        data_hash = kwargs['data_hash']
        try:
            score = self._predict(bytez, data_hash)
            ret = score > self.clsf_threshold
        except:
            ret = None
        return ret

    def predict_proba(self, graph):
        return self.model(graph)

    def _predict(self, bytez: bytes, data_hash: str):

        tmp_sample_path = os.path.join(self.config.tmp_sample_root, data_hash)
        if not os.path.exists(tmp_sample_path+".json"):
            if not os.path.exists(tmp_sample_path):
                with open(tmp_sample_path, 'wb') as out:
                    out.write(bytez)
            self.handle_acfg(tmp_sample_path)

        with open(tmp_sample_path+".json", "r+", encoding="utf-8") as file:
            data_item = jsonlines.Reader(file).read()

        acfg_list = data_item['acfg_list']
        graph = transform_acfg_list_to_graph(acfg_list).to(self.config.device)

        # 当前图为空图时，直接返回
        if graph.x.size(0) == 0 or graph.edge_index.size(1) == 0:   # 无节点或无边
            return torch.tensor(1.0, device=self.config.device)

        score = self.model(graph)

        if __TEST__:
            print(graph.edge_index.shape)
            print(graph.detach().cpu().x.numpy())

        return score

    def get_score(self, bytez, data_hash):
        score = float(self._predict(bytez, data_hash))
        return score 

    def handle_acfg(self, tmp_sample_path):
        cmd = self.config.IDA_PATH + ' -c -A -S' + self.config.SCRIPT_PATH + ' ' + tmp_sample_path
        p = subprocess.Popen(cmd, shell=True)
        p.wait()

