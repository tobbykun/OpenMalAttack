import re
import os
import glob
import hashlib
import json
from pathlib import Path
from sklearn.model_selection import train_test_split

SAMPLE_PATH = {}
DATA_SPLIT = "xxx/malware_le_3000Blocks.json"       # FIXME

def get_available_sha256():
    """从文件夹内获取可用的样本"""
    sha256_list = []
    for file_path in glob.glob(os.path.join(SAMPLE_PATH, '*')):
        file_name = os.path.split(file_path)[-1]
        result = re.match(r'^[0-9a-fA-F]{64}$', file_name)
        if result:
            sha256_list.append(result.group(0))
    assert len(sha256_list) > 0, "no files found in {} with sha256 names".format(SAMPLE_PATH)
    return sha256_list


def fetch_file(file):
    """读取一个样本文件"""
    location = os.path.join(file)
    try:
        with open(location, 'rb') as infile:
            bytez = infile.read()
    except IOError:
        raise "Unable to read sha256 from {}".format(location)
    except:
        print("Unable to load file")
    return bytez

def calc_sha256(bytez: bytes) -> str:
    """计算新样本的sha256值"""
    m = hashlib.sha256()
    m.update(bytez)
    sha256 = m.hexdigest()
    return sha256

def save_evaded_sample(output_path, sha256, bytez):
    """将成功绕过的样本写入文件"""
    evade_path = Path(output_path, sha256)
    evade_path.parent.mkdir(parents=True, exist_ok=True)
    evade_path.write_bytes(bytez)

def get_rl_dataset():
    all_data_json = json.load(open(DATA_SPLIT, 'r'))
    # return list(all_data_json['train_malware']),list(all_data_json['valid_malware']),list(all_data_json['test_malware'])
    dataset = list(all_data_json['ls_than_3000_Blocks'])[:]
    for i,dt in enumerate(dataset):
        dataset[i] = os.path.basename(dt)
        SAMPLE_PATH.update({dataset[i]: os.path.dirname(dt)})
    labels = [1]*len(dataset)

    x_train, _, y_train, y_test = train_test_split(dataset, labels, random_state=124, test_size = 0.2)
    test_json = json.load(open("xxx/Projects/Test1019_malware_le_3000Blocks.json", 'r'))
    x_test = list(test_json['ls_than_3000_Blocks'])[:5000]
    for i,dt in enumerate(x_test):
        x_test[i] = os.path.basename(dt)
        SAMPLE_PATH.update({x_test[i]: os.path.dirname(dt)})
    return x_train, [], x_test

if __name__ == '__main__':
    # save_evaded_sample('/tmp/evaded', '0fff', b'ELF')
    get_rl_dataset()