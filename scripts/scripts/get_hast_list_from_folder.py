import os
import json
import jsonlines

def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)


f = open('XXX/get_test_dataset_acfg/benign_hash.txt', 'r')
line = f.readline()
while line:
    filename = json.loads(line.strip())
    cmd = 'find /home/benign_data -name ' + filename
    path = os.popen(cmd).read().strip()
    if path!='':
        # print(path)
        write_data_to_filename('XXX/get_test_dataset_acfg/benign_hash_list_path.txt',path)
    line = f.readline()
f.close()