import glob
import os
import subprocess
import json
import jsonlines
from multiprocessing import Pool

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
    hash_to_path = get_data('XXX/get_test_dataset_acfg/hash_list/mal_hash_to_path.txt')
    cmd_list = []
    f = open('XXX/get_test_dataset_acfg/hash_list/test_mal_hash.txt', 'r')
    line = f.readline()
    while line:
        data_hash = json.loads(line.strip())
        hash_path = hash_to_path[data_hash]
        cmd = 'cp ' + hash_path + ' XXX/mal_benign_data/test/test_mal_data'
        cmd_list.append(cmd)
        line = f.readline()
    f.close()

    with Pool(processes = 80) as p:
        p.map(obtain_acfg,cmd_list)


if __name__ == '__main__':
    main()
