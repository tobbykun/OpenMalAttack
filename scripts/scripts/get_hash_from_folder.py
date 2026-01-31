import os
import json
import jsonlines
import glob
def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

target_path = "XXX/train/train_benign_acfg_files"

for f in glob.glob(target_path + '/*'):
    data_hash_with_path = f.split('.')[0]
    data_hash = data_hash_with_path.split('/')[-1]
    write_data_to_filename("XXX/train_benign_hash.txt", data_hash)