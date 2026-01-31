import glob
import networkx as nx
import copy
import jsonlines

MIN_NODE_NUMBER = 1


def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)


for file in glob.glob(dll_dir):
    f = open(file)
    line = f.readline()
    while line:
        line = json.loads(line)
        start_node = line['function_edges'][0]
        end_node = line['function_edges'][1]
        total_node = set(start_node + end_node)  # 所有连通子图的函数节点
        function_call_graph = nx.DiGraph()
        for i in range(len(start_node)):
            source = start_node[i]
            target = end_node[i]
            function_call_graph.add_node(source)
            function_call_graph.add_node(target)
            function_call_graph.add_edge(source, target)
        undirected_function_call_graph = function_call_graph.to_undirected()  # 把有向图转换为无向图
        # 获取相互连通的部分
        connected_graph = list(nx.connected_components(undirected_function_call_graph))

        # 获取所有有向连通子图
        total_sub_graph = []
        for graph_item in connected_graph:
            if len(graph_item) <= MIN_NODE_NUMBER:  # 子图中的节点小于MIN_NODE_NUMBER
                continue
            total_node -= graph_item  # 得到最后需要删除的函数节点
            sub_graph = function_call_graph.subgraph(list(graph_item))
            total_sub_graph.append(sub_graph)

        function_names = copy.deepcopy(line['function_names'])
        acfg_list = copy.deepcopy(line['acfg_list'])

        # 遍历需要删除的函数节点, 这里需要从后向前删
        for index in sorted(total_node, reverse=True):
            if index < len(acfg_list):
                del acfg_list[index]
            del function_names[index]

        # 获取新的function_edges
        start_node = []
        end_node = []
        for sub_graph in total_sub_graph:
            for item in list(sub_graph.edges):
                start_index = function_names.index(line['function_names'][item[0]])  # 通过函数名找到index
                end_index = function_names.index(line['function_names'][item[1]])
                start_node.append(start_index)
                end_node.append(end_index)

        data = {'hash': line['hash'], 'function_number': len(function_names),
                'function_edges': [start_node, end_node], 'function_names': function_names,
                'acfg_list': acfg_list}
        write_data_to_filename("result_new.jsonl", data)
        line = f.readline()
    f.close()


