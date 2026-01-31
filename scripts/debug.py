from idaapi import *
from idautils import *
import idc
import networkx as nx
import cfg_constructor as cfg
import cPickle as pickle
import pdb
import time
from raw_graphs import *
from discovRe import *
import time
import logging
import jsonlines
logging.basicConfig(filename='../logs/debug.log', level=logging.INFO, filemode='a')

def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

def get_seg_list():
	"""
	获取seg, 1 表示 XTRN, 7 表示 SEG_NULL
	"""
	result = []
	total_seg_number = get_segm_qty()
	for n in range(total_seg_number):
		seg = getnseg(n)
		ea = seg.startEA
		seg_type = segtype(ea)
		if seg_type in [1, 3, 7, 8, 9]:
			continue
		result.append(seg)
	return result


def get_func_cfgs_c(start_time):
    """
    ea: binary的起始地址
    return: 每个函数的原生属性控制流图（未向量化）的列表
    """
    binary_name = GetInputFile()
    
    # raw_graphs用于存放raw_graph对象
    raw_cfgs = raw_graphs(binary_name)
    # 得到外部函数的起始地址和名称，对PE文件这个函数只会得到空集, (这个对于目前来说没什么用)
    externs_eas, ea_externs = processpltSegs()
    
    seg_list = get_seg_list()
    flag = False
    i = 0
    for segm in seg_list:
        for funcea in Functions(segm.startEA, segm.endEA):
            funcname = get_unified_funcname(funcea)
            func = get_func(funcea)  # 得到func这个类对象
            write_data_to_filename('../logs/debug.log', func)
            # icfg是函数的cfg
            icfg = cfg.getCfg(func, externs_eas, ea_externs)
			


def get_unified_funcname(ea):
	"""
	得到统一形式的functionName
	如果function name的第一位是`.`, 则去除
	"""
	funcname = GetFunctionName(ea)
	return funcname
	# print("origin function name: ", funcname)
	# if len(funcname) > 0:
	# 	if '.' == funcname[0]:
	# 		funcname = funcname[1:]
	# # print("final function name: ", funcname)
	# return funcname


def processpltSegs():
	"""
	得到外部函数对应的起始指令地址，以及外部函数起始地址对应的函数名
	对于目前的ACFG没什么用
	"""
	funcdata = {}
	datafunc = {}
	for n in xrange(get_segm_qty()):  # Segment总数
		seg = getnseg(n)
		ea = seg.startEA
		segname = SegName(ea)
		if segname in ['.plt', 'extern', '.MIPS.stubs']:  # 有外部函数的segment名称，这三个段都是ELF才有的
			start = seg.startEA
			end = seg.endEA
			cur = start
			while cur < end:
				name = get_unified_funcname(cur)
				funcdata[name] = hex(cur)
				datafunc[cur] = name
				cur = NextHead(cur)
	return funcdata, datafunc


if __name__ == '__main__':
    idaapi.autoWait()
    start_time = time.time()
    get_func_cfgs_c(start_time)
    idc.Exit(0)