# 由于多进程暂时无法传锁，故将提取出的acfg都单独保存在不同的json里，然后再用这个脚本合并成一个json，
# 然后把temp_acfg_files里的所有文件都删光
import jsonlines
import glob
def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)


base_dir = 'XXX/get_test_dataset_acfg/temp_acfg_files_before_call/'
target_name = 'XXX/get_test_dataset_acfg/test_malicious_before_call.json'
filepath_list = glob.glob(base_dir + '*.json')
for filepath in filepath_list:
    with open(filepath, "r+") as f:
        for item in jsonlines.Reader(f):
            write_data_to_filename(target_name,item)