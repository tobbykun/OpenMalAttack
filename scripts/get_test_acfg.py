# -*- coding: utf-8 -*- 
import glob
import os
import subprocess
import json
from multiprocessing import Pool, Process, Value, Lock
import omegaconf

cfg_path = "../configs/attack_mal.yaml"
config = omegaconf.OmegaConf.load(cfg_path)

def get_data(filename):
    with open(filename, 'r') as f:
        data = f.readline()
        data_list = json.loads(data.strip())
    f.close()
    return data_list

def obtain_acfg(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.wait()

def main():
    IDA_PATH = config.Acfg.IDA_PATH
    SCRIPT_PATH = config.Acfg.SCRIPT_PATH

    hash_to_path = get_data(config.Acfg.hash_to_path)
    f = open(config.Acfg.hash_list, 'r')
    line = f.readline()
    cmd_list = []
    i=0
    while line:
        filename = json.loads(line.strip())
        if filename.find(".") != -1:
            line = f.readline()
            continue

        
        fileee = os.path.join(config.Acfg.saved_path, filename + '.json')
        if os.path.exists(fileee):
            i+=1
            print(i)
            line = f.readline()
            continue
        
        data_path = hash_to_path[filename]
        cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + data_path
        # print(filename)
        cmd_list.append(cmd)
        line = f.readline()
    f.close()
    print(len(cmd_list))
    with Pool(processes = config.Acfg.num_workers) as p:
        p.map(obtain_acfg,cmd_list)


if __name__ == '__main__':
    main()
