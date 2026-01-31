# coding:utf-8
from func import *
from raw_graphs import *
import idc
import idaapi
import idautils
import os
import json
import networkx as nx
import jsonlines
import time
from multiprocessing import Lock

def read_data_from_jsonl(filename):
    """
    从jsonl读取数据
    """
    with open(filename, "r+") as f:
        for item in jsonlines.Reader(f):
            print(item)


def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)


def get_acfg():
    """
    获取ACFG
    """
    start_time = int(time.time())
    cfgs, flag = get_func_cfgs_c(start_time)
    if flag is True:
        with open('../logs/quit.log', 'a+') as f:
            f.write(GetInputFile() + ' time out; start_time: ' + str(start_time) + '; end_time: ' + str(int(time.time())) + '\n')
        f.close()
        idc.Exit(0)
    output = {}
    for func in cfgs.raw_graph_list:
        name = func.funcname
        features = func.discovre_features
        # fea = {'FunctionCalls': features[0], 'LogicInsts': features[1], 'TransferInsts': features[2],
        #        'LocalVariables': features[3], 'BasicBlocks': features[4], 'EdgeNumber': features[5],
        #        'IncommingCalls': features[6], 'Insts': features[7], 'between': features[8], 'strings': features[9],
        #        'consts': features[10], 'Edges': features[11]}
        block_start_node = []
        block_end_node = []
        # 边集
        for item in features[0]:
            block_start_node.append(item[0])
            block_end_node.append(item[1])

        a_fea = []
        for i in range(len(func.g.node)):
            each_node_features = func.g.node[i]['v']
            """
            0 -> numC0(数字个数) + nums1(字符串个数)
            1 -> offsprings(Total Edges)
            2 -> numAs(Arithmetic Instructions)
            3 -> numCalls
            4 -> numIns(Instructions)
            5 -> numLIs(Logic Instructions)
            6 -> numTIs(Transfer Instructions)
            7 -> numCmpIs(Compare Instructions)
            8 -> numMovIs(Mov Instructions),
            9 -> numTermIs(Termination Instructions)
            10 -> numDefIs(Data Definition Instructions)
            """
            # 在这里做了修改，将第0维改成numC0(数字个数)，第1维改成nums1(字符串个数)，删去offsprings
            # print(each_node_features[1])
            node = [len(each_node_features[0]), len(each_node_features[1]), each_node_features[2], each_node_features[3],
                    each_node_features[4], each_node_features[5], each_node_features[6], each_node_features[7],
                    each_node_features[8], each_node_features[9], each_node_features[10]]
            a_fea.append(node)
        fea = {'block_edges': [block_start_node, block_end_node], 'block_number': len(a_fea), 'block_features': a_fea}
        output.setdefault(name, fea)
    return output


def parse_gdl(filename, function_acfg):
    """
    解析gdl文件
    利用call graph获取到的函数把函数分为external和internal两类
    .开头的函数认为是external函数, 因为它的CFG比较简单，没有多少意义
    """
    # print('function_acfg', function_acfg)
    f = open(filename, 'r')
    line = f.readline()
    edge_list = []
    external_function = []  # 非internal_function
    internal_function = []  # ACFG 和 Call Graph的交集 - `.`开头的函数 - 红色的函数
    function_acfg_list = []
    order_function = []  # 根据 gdl 解析顺序的函数
    flag = True
    while line:
        data = line.strip('\n')
        if data.startswith('node:'):
            node_item_list = data.split(' ')
            function_name = node_item_list[5].replace('"', '')
            if function_name in function_acfg and node_item_list[7] != '80' and '.' != function_name[0]:
                internal_function.append(function_name)
                function_acfg_list.append(function_acfg[function_name])
            else:
                external_function.append(function_name)
            order_function.append(function_name)
        elif data.startswith('edge:'):
            node_item_list = data.split(' ')
            source = order_function[int(node_item_list[3].replace('"', ''))]
            target = order_function[int(node_item_list[5].replace('"', ''))]
            # if source in internal_function and target in internal_function:
            edge_list.append({'source': source, 'target': target})
        line = f.readline()
    f.close()
    # # internal + external 的函数
    total_function = internal_function + external_function
    return edge_list, total_function, function_acfg_list


def get_all_sub_graph(edge_list):
    """
    获取所有连通子图, 暂时不需要
    """
    big_cfg = nx.DiGraph()  # 有向图
    for item in edge_list:
        big_cfg.add_node(item['source'])  # 添加source节点
        big_cfg.add_node(item['target'])  # 添加target节点
        big_cfg.add_edge(item['source'], item['target'])  # 添加边
    # print('directed_nodes', big_cfg.nodes)
    # print('directed_edges', big_cfg.edges)
    undirected_big_cfg = big_cfg.to_undirected()  # 把有向图转换为无向图
    connected_graph = list(nx.connected_components(undirected_big_cfg))  # 获取无向图中的子图
    # connected_graph = connected_graph[0: 10]  # 获取前10个
    total_graph = []
    for graph_item in connected_graph:
        sub_graph = big_cfg.subgraph(list(graph_item))
        # print(sub_graph.nodes, sub_graph.edges)
        total_graph.append(list(sub_graph.edges))
    return total_graph


if __name__ == '__main__':
    idaapi.autoWait()
    # args = parse_command()
    # path = args.path
    base_dir = "../logs"
    dst_path = os.path.join(base_dir, 'dst')
    gdl_path = "../dataset/gdl/"
    call_graph_and_acfg_filename = os.path.join(base_dir, 'test_malicious.json')
    pe_filename = GetInputFile()  # 获取文件名
    start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    output = get_acfg()  # 获取 ACFG
    print(output)
    gdl_filename = gdl_path + pe_filename
    res = idaapi.gen_simple_call_chart(gdl_filename, '', 'title', 0)  # 获取call graph
    if res is True:
        # 解析gdl文件
        edge_list, total_function, function_acfg_list = parse_gdl(gdl_filename + '.gdl', output)
    else:
        with open(os.path.join(base_dir, 'error.log'), 'a+') as f:
            f.write(pe_filename + ' get call graph failed\n')
        f.close()
        idc.Exit(0)

    function_start_node = []
    function_end_node = []
    for item in edge_list:
        function_start_node.append(total_function.index(item['source']))
        function_end_node.append(total_function.index(item['target']))

    data = {'hash': pe_filename, 'function_number': len(total_function),
            'function_edges': [function_start_node, function_end_node], 'function_names': total_function,
            'acfg_list': function_acfg_list}


    write_data_to_filename(call_graph_and_acfg_filename, data)

    end_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(os.path.join(base_dir, 'time.log'), 'a+') as f:
        f.write(pe_filename + ' start: ' + start_time + '; end: ' + end_time + '\n')
    f.close()
    idc.Exit(0)
