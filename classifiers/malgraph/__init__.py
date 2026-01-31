from classifiers.malgraph.ModelPredForAttack import *
from classifiers.base import Classifier
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from torch_geometric.data.batch import Batch

@dataclass
class configuration:
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    threshold_type = '100fpr'
    IDA_PATH = "The path to the directory containing idaq64."
    SCRIPT_PATH = "../../scripts/graph_handle_acfg.py"
    tmp_sample_root = "../..//dataset/tmp"
    IDA_TIMEOUT = 600  # seconds; IDA ACFG extraction timeout per file (avoid blocking forever)
    vocab_path = "../..//configs/train_external_function_name_vocab.jsonl"
    max_vocab_size = 10000
    model_path = "../..//models/malgraph/best_malgraph_model.pt"

    gnn_type="GraphSAGE"
    pool_type="global_max_pool"
    acfg_init_dims=11
    cfg_filters="200-200"
    fcg_filters="200-200"
    skip_att_heads=0
    number_classes=2
    dropout_rate=0.2
    ablation_models="Full"

class MalGraphClsf(Classifier):
    def __init__(self, **kwargs):
        self.__name__ = 'MalGraph'

        self.config = configuration()
        self.config.__dict__.update(kwargs)

        if self.config.threshold_type=='100fpr':
            self.clsf_threshold = 0.14346
        elif self.config.threshold_type=='1000fpr':
            self.clsf_threshold = 0.91276
        else:
            raise NotImplementedError
        
        self.vocab = Vocab(freq_file=self.config.vocab_path, max_vocab_size=self.config.max_vocab_size)
        _model_params = ModelParams(gnn_type=self.config.gnn_type, 
                                    pool_type=self.config.pool_type, 
                                    acfg_init_dims=self.config.acfg_init_dims, 
                                    cfg_filters=self.config.cfg_filters, 
                                    fcg_filters=self.config.fcg_filters,
                                    skip_att_heads=self.config.skip_att_heads,
                                    number_classes=self.config.number_classes,
                                    dropout_rate=self.config.dropout_rate,
                                    ablation_models=self.config.ablation_models)
        
        self.model = HierarchicalGraphNeuralNetwork(model_params=_model_params, external_vocab=self.vocab, global_log=None)

        self.model.load_state_dict(torch.load(self.config.model_path))  #, map_location=self.config.device
        self.model.to(self.config.device)
        self.model.eval()

    def __call__(self, *args, **kwargs):

        bytez = kwargs['bytez']
        data_hash = kwargs['data_hash']
        try:
            score = self._predict(bytez, data_hash)
            ret = score > self.clsf_threshold
        except:
            ret = None
        return ret
    
    def predict_proba(self, data_item):
        for i, item in enumerate(data_item['acfg_list']):
            for j, it in enumerate(item['block_features']):
                data_item['acfg_list'][i]['block_features'][j] = it[:-1]

        bt_pt = process_one_item(data_item, self.vocab)
        if bt_pt == None:
            return None
        bt = Batch.from_data_list([bt_pt])
        try:
            score = validate(local_device=self.config.device, one_batch_data=bt, model=self.model)
        except:
            print(data_item['acfg_list'])
            raise Exception("Something wrong in predict_proba!")
        return score

    def get_score(self, bytez, data_hash):
        score = float(self._predict(bytez, data_hash))
        return score 

    def _predict(self, bytez: bytes, data_hash: str):
        tmp_sample_path = os.path.join(self.config.tmp_sample_root, data_hash)
        timeout_sentinel = tmp_sample_path + '.timeout'
        if not os.path.exists(tmp_sample_path + ".json"):
            if os.path.exists(timeout_sentinel):
                raise RuntimeError(f'IDA previously timed out for {data_hash}; skip (sentinel exists).')
            if not os.path.exists(tmp_sample_path):
                with open(tmp_sample_path, 'wb') as out:
                    out.write(bytez)
            try:
                self.handle_acfg(tmp_sample_path)
            except RuntimeError as e:
                if 'timeout' in str(e).lower():
                    try:
                        open(timeout_sentinel, 'w').close()
                    except Exception:
                        pass
                raise

        with open(tmp_sample_path+".json", "r+", encoding="utf-8") as file:
            data_item = jsonlines.Reader(file).read()

        for i, item in enumerate(data_item['acfg_list']):
            for j, it in enumerate(item['block_features']):
                data_item['acfg_list'][i]['block_features'][j] = it[:-1]

        bt_pt = process_one_item(data_item, self.vocab)
        if bt_pt == None:
            return None
        bt = Batch.from_data_list([bt_pt])
        score = validate(local_device=self.config.device, one_batch_data=bt, model=self.model)
        return score

    def handle_acfg(self, tmp_sample_path):
        cmd = self.config.IDA_PATH + ' -c -A -S' + self.config.SCRIPT_PATH + ' ' + tmp_sample_path
        timeout = getattr(self.config, 'IDA_TIMEOUT', 600)
        kwargs = {'shell': True}
        if sys.platform != 'win32':
            kwargs['start_new_session'] = True
        p = subprocess.Popen(cmd, **kwargs)
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                if sys.platform != 'win32' and hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                else:
                    p.kill()
            except Exception:
                p.kill()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise RuntimeError(
                f'IDA ACFG extraction timeout ({timeout}s) for {tmp_sample_path}; '
                'killed. Increase config IDA_TIMEOUT or skip slow samples.'
            )


