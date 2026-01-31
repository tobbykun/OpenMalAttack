from dataclasses import dataclass
import torch
from datetime import datetime
from torch import nn
from torch.nn import Conv1d, MaxPool1d, Linear
from torch.nn import functional as F
from torch_geometric.nn.conv import GCNConv
from torch_geometric.nn.glob import global_sort_pool
from torch_geometric.data import DataLoader, Dataset, InMemoryDataset, Data, Batch
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score, roc_curve
from utils.magic.TheGCN import GCN
from sklearn.metrics import auc, confusion_matrix, balanced_accuracy_score
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score, roc_curve
from utils.magic.get_graph.acfg_pipeline import processGetACFG


def process_one_item(raw_path):
    graph_labels = []
    node_attributes = []
    edge_index = []
    start_index = []
    end_index = []

    f = open(raw_path, 'r')
    line = f.readline().strip().split(' ')
    total_node_number, label = int(line[0]), int(line[1])
    graph_labels.append(label)
    for node_number in range(total_node_number):
        data = next(f).strip().split(" ")
        data = [float(x) for x in data]
        node_attributes.append(data[-11:])
        edges = data[1: int(data[0]) + 1]
        for item in edges:
            start_index.append(node_number)
            end_index.append(item)
    edge_index.append(start_index)
    edge_index.append(end_index)
    y = torch.tensor(graph_labels, dtype=torch.int64)
    x = torch.tensor(node_attributes, dtype=torch.float32)
    edge_index = torch.tensor(edge_index, dtype=torch.int64)
    data = Data(x=x, edge_index=edge_index, y=y)
    return data


def p(model, device, data):
    model.eval()
    true_list = []
    pred_list = []

    data = data.to(device)
    out = model(data.x, data.edge_index, data.batch)
    pred = torch.squeeze(out, -1)
    return pred.item()


