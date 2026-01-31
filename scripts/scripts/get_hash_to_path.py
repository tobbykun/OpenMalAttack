import os
import json
import jsonlines

def write_data_to_filename(data, filename):
    with open(filename, 'a') as f:
        f.write(json.dumps(data))
    f.close()
hash_to_path = {}

f = open('XXX/get_test_dataset_acfg/hash_list_path/all_benign_hash_list_path.txt', 'r')
line = f.readline()
while line:
    path = json.loads(line.strip())
    data_hash = path.split('/')[-1]
    hash_to_path[data_hash] = path
    line = f.readline()
f.close()

f = open('XXX/get_test_dataset_acfg/hash_list_path/all_malicious_hash_list_path.txt', 'r')
line = f.readline()
while line:
    path = json.loads(line.strip())
    data_hash = path.split('/')[-1]
    hash_to_path[data_hash] = path
    line = f.readline()
f.close()

write_data_to_filename(hash_to_path, 'XXX/get_test_dataset_acfg/hash_list/all_hash_to_path.txt')