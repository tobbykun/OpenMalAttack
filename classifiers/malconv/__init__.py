import os
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable
from dataclasses import dataclass
from classifiers.base import Classifier

@dataclass
class configuration:
    use_gpu = True
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model_file = "../../malconv/malconv_epoch99_0.07830339506414603.pt"
    threshold_type = '100fpr'

class GateConv1d(nn.Module):
    def __init__(self, maxlen):
        super(GateConv1d, self).__init__()

        self.conv1 = nn.Conv1d(8, 128, 500, stride=500, bias=True)
        self.conv2 = nn.Conv1d(8, 128, 500, stride=500, bias=True)
        self.pooling = nn.MaxPool1d(int(maxlen / 500))

    def forward(self, x):
        x = torch.transpose(x, -1, -2)
        x = self.pooling(F.relu(self.conv1(x))*torch.sigmoid(self.conv2(x)))
        x = x.view(-1, 128)
        return x

class MalConv(nn.Module):
    def __init__(self, maxlen):
        super(MalConv, self).__init__()
        self.malconv = torch.nn.Sequential(
            torch.nn.Embedding(257, 8), GateConv1d(maxlen),
            torch.nn.Linear(128, 128), torch.nn.ReLU(),
            torch.nn.Linear(128, 1), torch.nn.Sigmoid()#torch.nn.Dropout(0.3), 
        )

    def forward(self, x):
        return self.malconv(x)


class MalConvClsf(Classifier):
    def __init__(self, **kwargs):
        super(MalConvClsf, self).__init__(**kwargs)
        self.__name__ = 'MalConv'

        self.config = configuration()
        self.config.__dict__.update(kwargs)

        if self.config.threshold_type=='100fpr':
            self.clsf_threshold = 0.26796
        elif self.config.threshold_type=='1000fpr':
            self.clsf_threshold = 0.95666
        else:
            raise NotImplementedError

        self.input_length = 2**21
        self.padding_char = 256
        self.model = MalConv(self.input_length)
        self.model.load_state_dict({k.replace('module.',''):v for k,v in torch.load(self.config.model_file).items()})
        self.model.to(self.config.device)
        self.model.eval()
        
    def __call__(self, bytez) -> bool:
        """
        return labels
        """
        score = self.predict_prob(self.extract(bytez))
        return score > self.clsf_threshold

    def _predict(self, bytez) -> bool:
        """
        return labels
        """
        score = self.predict_prob(self.extract(bytez))
        return score

    def extract(self, bytez) -> list:

        new_bytez = []
        if isinstance(bytez, bytes):
            new_bytez.append(bytez)
        else:
            new_bytez = bytez
        for i in range(len(new_bytez)):
            b = np.ones( (self.input_length,), dtype=np.int32 )*self.padding_char   #uint16
            bz = np.frombuffer( new_bytez[i][:self.input_length], dtype=np.uint8 )
            b[:len(new_bytez[i])] = bz
            new_bytez[i] = b
        return np.array(new_bytez)

    def predict_prob(self, sample: torch.tensor) -> list:
        """
        return scores
        """
        tensor = sample
        if isinstance(sample, np.ndarray):
            tensor = torch.from_numpy(np.array(tensor))

        tensor = Variable(tensor, requires_grad=False)
        tensor = tensor.to(self.config.device)
        res = self.model(tensor).squeeze(dim=1)
        return res
    
    def get_score(self, bytez, data_hash=None) -> float:
        """
        Unified scoring interface used by some attackers (e.g., MakeOver).
        Returns a scalar score (malicious probability).
        """
        score = self.predict_prob(self.extract(bytez))
        if hasattr(score, "item"):
            return float(score.item())
        return float(score)
        
    def get_score_with_grad(self, bytez, data_hash=None):
        """
        Return (embed_x, embed_x_grad, score) similar to MalconvClient(grad_output=True).
        embed_x / embed_x_grad are flattened lists for compatibility with judge_grad.
        """
        # Prepare input indices
        sample = self.extract(bytez)
        tensor = torch.from_numpy(np.array(sample)).long().to(self.config.device)

        # Split model into embedding and the rest
        emb_layer = self.model.malconv[0]
        rest = nn.Sequential(*list(self.model.malconv)[1:])

        # Get embeddings with grad
        inp_idx = tensor
        emb = emb_layer(inp_idx)
        emb = emb.detach()
        emb.requires_grad_(True)

        out = rest(emb).squeeze()
        score = out if out.ndim == 0 else out[0]

        # Backprop to embeddings
        self.model.zero_grad(set_to_none=True)
        if emb.grad is not None:
            emb.grad.zero_()
        score.backward()

        emb_np = emb.detach().cpu().numpy().astype(float).ravel()
        grad_np = emb.grad.detach().cpu().numpy().astype(float).ravel()

        embed_x = emb_np.tolist()
        embed_x_grad = grad_np.tolist()
        return embed_x, embed_x_grad, float(score.detach().cpu().item())


if __name__ == "__main__":
    malconv = MalConvClsf()