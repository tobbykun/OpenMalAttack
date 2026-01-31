from idaapi import *
from idautils import *
from idc import *
import idc
import networkx as nx
import cfg_constructor as cfg
import cPickle as pickle
import pdb
import time
from raw_graphs import *
from discovRe import *
import jsonlines

__MODIFY__ = True

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

			# icfg是函数的cfg
			icfg = cfg.getCfg(func, externs_eas, ea_externs)  
			
			i = i + 1
			end_time = int(time.time())
			# print('time diff', i, hex(funcea), 'get_icfg', end_time, start_time, end_time - start_time)
			# func_f是边，[(A,B),(C,D)] A->B C->D，这种形式，这个边我不知道有什么用
			func_f = get_discoverRe_feature(funcea, func, icfg)  # 以函数为单位生成DiscoverRe中的函数特征
			# 这里是能提取出被
			blocks = [(hex(v.startEA), hex(v.endEA)) for v in FlowChart(func)]
			Insts = getIntrs(func)
			# write_data_to_filename('/home/wzy/get_test_dataset_acfg/debug.log', str([funcname, blocks]))
			if func_f is None:
				flag = True
				break
			# print('time diff', i, hex(funcea), 'get_func_f', end_time, start_time, end_time - start_time)
			end_time = int(time.time())
			if end_time - start_time >= 300:
				flag = True
				break
			raw_g = raw_graph(funcname, icfg, func_f)  # 整合
			raw_cfgs.append(raw_g)
			
		if flag is True:
			break
	
	return raw_cfgs, flag


def get_unified_funcname(ea):
	"""
	得到统一形式的functionName
	如果function name的第一位是`.`, 则去除
	"""
	funcname = GetFunctionName(ea)
	return funcname


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
