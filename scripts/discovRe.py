import networkx as nx
import cPickle as pickle
import pdb
from graph_analysis_ida import *
from graph_property import *


def get_discoverRe_feature(funcea, func, icfg):
    NumberOfFuncCalls, NumberOfLogicInsts, NumberOfTransferInsts, NumberOfIntrs = get_all_contributes(func)
    if NumberOfFuncCalls == -1 and NumberOfLogicInsts == -1 and NumberOfTransferInsts == -1 and NumberOfIntrs == -1:
        return None
    features = []
    
    Edges = icfg.edges()

    edge_block = []
    for ed in Edges:
        edge_block.append(ed)
    features.append(edge_block)
    return features
