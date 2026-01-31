import json
import logging
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict

import matplotlib
import numpy as np

matplotlib.use('Agg')

import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import auc, confusion_matrix, balanced_accuracy_score
from texttable import Texttable
from datetime import datetime


# matplotlib.rcParams['font.sans-serif'] = ['Source Han Sans TW', 'sans-serif']

def only_get_fpr(y_true, y_pred):
    n_benign = (y_true == 0).sum()
    n_false = (y_pred[y_true == 0] == 1).sum()
    return float(n_false) / float(n_benign)


def get_fpr(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true=y_true, y_pred=y_pred).ravel()
    return float(fp) / float(fp + tn)


def find_threshold_with_fixed_fpr(y_true, y_pred, fpr_target):
    start_time = datetime.now()
    
    threshold = 0.0
    fpr = only_get_fpr(y_true, y_pred > threshold)
    while fpr > fpr_target and threshold <= 1.0:
        threshold += 0.0001
        fpr = only_get_fpr(y_true, y_pred > threshold)
    
    tn, fp, fn, tp = confusion_matrix(y_true=y_true, y_pred=y_pred > threshold).ravel()
    tpr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    acc = (tp + tn) / (tn + fp + fn + tp)  # equal to accuracy_score(y_true=y_true, y_pred=y_pred > threshold)
    balanced_acc = balanced_accuracy_score(y_true=y_true, y_pred=y_pred > threshold)
    
    _info = "Threshold: {:.6f}, TN: {}, FP: {}, FN: {}, TP: {}, TPR: {:.6f}, FPR: {:.6f}, ACC: {:.6f}, Balanced_ACC: {:.6f}. consume about {} time in find threshold".format(
        threshold, tn, fp, fn, tp, tpr, fpr, acc, balanced_acc, datetime.now() - start_time)
    return _info


def alphabet_lower_strip(str1):
    return re.sub("[^A-Za-z]", "", str1).lower()


def filter_counter_with_threshold(counter: Counter, min_threshold):
    return {x: counter[x] for x in counter if counter[x] >= min_threshold}


def create_dir_if_not_exists(new_dir: str, log: logging.Logger):
    if not os.path.exists(new_dir):
        os.makedirs(new_dir)
        log.info('We are creating the dir of \"{}\" '.format(new_dir))
    else:
        log.info('We CANNOT creat the dir of \"{}\" as it is already exists.'.format(new_dir))


def get_jsonl_files_from_path(file_path: str, log: logging.Logger):
    file_list = []
    for root, dirs, files in os.walk(file_path):
        for file in files:
            if file.endswith(".jsonl"):
                file_list.append(os.path.join(root, file))
    file_list.sort()
    log.info("{}\nFrom the path of {}, we obtain a list of {} files as follows.".format("-" * 50, file_path, len(file_list)))
    log.info("\n" + '\n'.join(str(f) for f in file_list))
    return file_list


def write_into(file_name_path: str, log_str: str, print_flag=True):
    if print_flag:
        print(log_str)
    if log_str is None:
        log_str = 'None'
    if os.path.isfile(file_name_path):
        with open(file_name_path, 'a+') as log_file:
            log_file.write(log_str + '\n')
    else:
        with open(file_name_path, 'w+') as log_file:
            log_file.write(log_str + '\n')


def params_print_log(param_dict: Dict, log_path: str):
    keys = sorted(param_dict.keys())
    table = Texttable()
    table.set_precision(6)
    table.set_cols_align(["l", "l", "c"])
    table.add_row(["Index", "Parameters", "Values"])
    for index, k in enumerate(keys):
        table.add_row([index, k, str(param_dict[k])])
    
    # print(table.draw())
    write_into(file_name_path=log_path, log_str=table.draw())


def dataclasses_to_string(ins: dataclass):
    name = type(ins).__name__
    
    var_list = [f"{key} = {value}" for key, value in vars(ins).items()]
    var_str = '\n=>'.join(var_list)
    
    return f"{name}:\n=>{var_str}\n"


def plot_dataset_statistics(sts_file: str):
    no_nodes_fcg_list = {"Benign_ALL": [], "Malware_ALL": []}
    total_no_cfg_list = {"Benign_ALL": [], "Malware_ALL": []}
    sum_no_nodes_cfg_list = {"Benign_ALL": [], "Malware_ALL": []}
    avg_no_node_per_cfg_list = {"Benign_ALL": [], "Malware_ALL": []}
    
    with open(sts_file, "r+", encoding="utf-8") as file:
        sts_list = json.loads(file.read())
        print(type(sts_list), len(sts_list))
        print(sts_list[0])
        for one_sts in sts_list:
            flag = one_sts['flag']  # "Benign_ALL" or "Malware_ALL"
            no_nodes_fcg = one_sts['No.Nodes.FCG']
            total_no_cfg = one_sts['Total.No.CFG']
            sum_no_nodes_cfg = one_sts['Sum.No.Nodes.CFG']
            if len(one_sts["Node.Edge.CFG.List"]) <= 0.01:
                print(one_sts['Sum.No.Nodes.CFG'], len(one_sts["Node.Edge.CFG.List"]))
            else:
                avg_no_node_per_cfg = float(one_sts['Sum.No.Nodes.CFG'] / len(one_sts["Node.Edge.CFG.List"]))
            
            no_nodes_fcg_list[flag].append(no_nodes_fcg)
            total_no_cfg_list[flag].append(total_no_cfg)
            sum_no_nodes_cfg_list[flag].append(sum_no_nodes_cfg)
            avg_no_node_per_cfg_list[flag].append(avg_no_node_per_cfg)
    
    # drawing
    bin_width = 10
    plt.figure()
    sns.color_palette()
    # stat="probability", cumulative=True, binrange=[0, 2000]
    sns.histplot(no_nodes_fcg_list['Malware_ALL'], label="Malware_ALL", binwidth=bin_width, color="orangered", stat="probability", cumulative=True, binrange=[0, 3000])
    sns.histplot(no_nodes_fcg_list['Benign_ALL'], label="Benign_ALL", binwidth=bin_width, color="lightseagreen", stat="probability", cumulative=True, binrange=[0, 3000])
    plt.xlabel("number of nodes (bin_width = {})".format(bin_width))
    plt.title('no_nodes_fcg_list: Avg Malware={:.2f}, Avg Benign={:.2f}, Avg ALL={:.2f}'.format(np.mean(no_nodes_fcg_list['Malware_ALL']), np.mean(no_nodes_fcg_list['Benign_ALL']),
                                                                                                np.mean(no_nodes_fcg_list['Malware_ALL'] + no_nodes_fcg_list['Benign_ALL'])))
    plt.legend()
    plt.savefig("1_cum_{}_distribution.png".format("no_nodes_fcg_list"), dpi=300, pad_inches=0, bbox_inches='tight')
    
    # drawing
    bin_width = 100
    plt.figure()
    sns.color_palette()
    # stat="probability", cumulative=True, binrange=[0, 20000]
    sns.histplot(sum_no_nodes_cfg_list['Malware_ALL'], label='Malware_ALL', binwidth=bin_width, color="orangered", stat="probability", cumulative=True, binrange=[0, 30000])
    sns.histplot(sum_no_nodes_cfg_list['Benign_ALL'], label='Benign_ALL', binwidth=bin_width, color="lightseagreen", stat="probability", cumulative=True, binrange=[0, 30000])
    plt.xlabel("number of nodes (bin_width = {})".format(bin_width))
    plt.title('sum_no_nodes_cfg_list: Avg Malware={:.2f}, Avg Benign={:.2f}, Avg ALL={:.2f}'.format(np.mean(sum_no_nodes_cfg_list['Malware_ALL']),
                                                                                                    np.mean(sum_no_nodes_cfg_list['Benign_ALL']),
                                                                                                    np.mean(sum_no_nodes_cfg_list['Malware_ALL'] + sum_no_nodes_cfg_list[
                                                                                                        'Benign_ALL'])))
    plt.legend()
    plt.savefig("2_cum_{}_distribution.png".format("sum_no_nodes_CFG_list"), dpi=300, pad_inches=0, bbox_inches='tight')
    
    # drawing
    bin_width = 1
    plt.figure()
    sns.color_palette()
    sns.histplot(avg_no_node_per_cfg_list['Malware_ALL'], label="Malware_ALL", binwidth=bin_width, color="orangered", stat="probability", cumulative=True)
    sns.histplot(avg_no_node_per_cfg_list['Benign_ALL'], label="Benign_ALL", binwidth=bin_width, color="lightseagreen", stat="probability", cumulative=True)
    plt.xlabel("number of nodes (bin_width = {})".format(bin_width))
    plt.title('avg_no_node_per_CFG_list: Avg Malware={:.2f}, Avg Benign={:.2f}, Avg ALL={:.2f}'.format(np.mean(avg_no_node_per_cfg_list['Malware_ALL']),
                                                                                                       np.mean(avg_no_node_per_cfg_list['Benign_ALL']),
                                                                                                       np.mean(avg_no_node_per_cfg_list['Malware_ALL'] + avg_no_node_per_cfg_list[
                                                                                                           'Benign_ALL'])))
    plt.legend()
    plt.savefig("3_cum_prob_{}_distribution.png".format("avg_no_node_per_CFG_list"), dpi=300, pad_inches=0, bbox_inches='tight')


def plot_loss_and_text(loss_list: list, vis_text: str, flag: str):
    # sns.set('talk', 'whitegrid', 'dark', font_scale=1, font='DejaVu Sans', rc={"lines.linewidth": 2, 'grid.linestyle': '--'})
    sns.set()
    
    lw = 2
    batch_index = range(len(loss_list))
    fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(20, 10))
    ax1, ax2 = axes
    ax1.plot(batch_index, loss_list, color='darkorange', lw=lw, label='Loss')
    # ax1.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
    ax1.set_xlabel('Batch Index')
    ax1.set_ylabel('Loss')
    ax1.set_title('{}\'s Loss Value'.format(flag))
    ax1.legend(loc="lower right")
    
    ax2.set_title('{}\'s results'.format(flag))
    ax2.text(0, 0, vis_text, wrap=False)
    
    # plt.show()
    fig.savefig('{}.png'.format(flag))


def plot_roc_auc_and_text(tpr: list, fpr: list, vis_text: str, flag: str):
    # sns.set('talk', 'whitegrid', 'dark', font_scale=1, font='DejaVu Sans', rc={"lines.linewidth": 2, 'grid.linestyle': '--'})
    sns.set()
    _calculated_roc_auc = auc(fpr, tpr)
    
    lw = 2
    fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(20, 10))
    ax1, ax2 = axes
    ax1.plot(fpr, tpr, color='darkorange', lw=lw, label='ROC curve (AUC = {:0.4f})'.format(_calculated_roc_auc))
    ax1.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
    ax1.set_xlim(-0.01, 1.05)
    ax1.set_ylim(-0.01, 1.05)
    ax1.set_xlabel('FPR (False Positive Rate)')
    ax1.set_ylabel('TPR (True  Positive Rate)')
    ax1.set_title('{}\'s ROC AUC Curve'.format(flag))
    ax1.legend(loc="lower right")
    
    ax2.set_xlim(-0.01, 1.05)
    ax2.set_ylim(-0.01, 1.05)
    ax2.set_title('{}\'s results'.format(flag))
    ax2.text(0, 0, vis_text, fontsize=10, wrap=True)
    
    # plt.show()
    fig.savefig('{}.png'.format(flag))


if __name__ == '__main__':
    TPR = [0, 0.03125, 0.0625, 0.0625, 0.09375, 0.09375, 0.15625, 0.15625, 0.1875, 0.1875, 0.3125, 0.3125, 0.375, 0.375, 0.4375, 0.4375, 0.46875, 0.5625, 0.5625, 0.59375, 0.59375,
           0.625, 0.625, 0.6875, 0.6875, 0.78125, 0.78125, 0.8125, 0.8125, 0.875, 0.9375, 0.9375, 0.96875, 0.96875, 1., 1.]
    FPR = [0., 0., 0., 0.03125, 0.03125, 0.0625, 0.0625, 0.09375, 0.09375, 0.15625, 0.15625, 0.1875, 0.1875, 0.21875, 0.21875, 0.3125, 0.34375, 0.375, 0.53125, 0.53125, 0.59375,
           0.59375, 0.625, 0.625, 0.71875, 0.71875, 0.78125, 0.78125, 0.8125, 0.8125, 0.8125, 0.84375, 0.84375, 0.96875, 0.96875, 1.]
    text = "Results:\n    Epoch_Index=train_2_0    Sum_Avg_Loss=2.7520663738250732\n\t    ACC=0.625    Balanced_ACC=0.625    ROC_AUC_score=0.671875    "
    # plot_roc_auc_and_text(tpr=TPR, fpr=FPR, vis_text=text, flag="xxx")
    # plot_loss_and_text(loss_list=TPR, vis_text=text, flag='loss')
    
    txt = "/home/newdisk/lx_11521065/MalAttack/MalGraph/processed_dataset/all_raw_statistics.txt"
    plot_dataset_statistics(sts_file=txt)
