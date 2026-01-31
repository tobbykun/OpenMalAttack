import glob
import os
import subprocess
import json

def main():
    IDA_PATH = 'XXX/IDA_Pro_v6.4/idaq64'
    SCRIPT_PATH = 'XXX/call_graph_and_acfg_wd/call_graph_and_acfg/processing_ida_new.py'
    FILE_PATH = 'xxx/benign_data/origin_less_than_2MB/exe/*'
        
    f = open('XXX/get_test_dataset_acfg/benign_hash_list_path.txt', 'r')
    line = f.readline()
    i=0
    while line:
        filename = json.loads(line.strip())
        if filename.find(".") != -1:
            continue
        cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + filename
        p = subprocess.Popen(cmd, shell=True)
        p.wait()
        line = f.readline()
    f.close()


if __name__ == '__main__':
    main()
