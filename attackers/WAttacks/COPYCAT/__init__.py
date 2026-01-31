import numpy as np
import torch
import torchvision
from torchvision import transforms
import os
import pandas as pd
from ThirdParty.CW.l2 import carlini_wagner_l2

from classifiers.base import Classifier
from attackers.base import Problem_Space
from dataclasses import dataclass
import time
import random
import PIL
import io


# 只加入COPYCAT的CW实现
class COPYCAT(Problem_Space):
    def __init__(self, **kwargs):
        super(COPYCAT, self).__init__()
        self.__name__ = "COPYCAT"
        self.reset()

    # Attack convNet
    def __call__(self, clsf: Classifier, input_: bytes):
        self._attack_begin()
        self.setup_seed(10086)

        myTransform = transforms.Compose([
            transforms.Resize([250, 100]),
            transforms.Grayscale(1),
            transforms.ToTensor()
        ])
        resize = transforms.Resize([250, 100])

        # 优先尝试把 bytes 当作真实图片文件解码；失败再退化为 frombuffer 方式
        try:
            image = PIL.Image.open(io.BytesIO(input_))
        except Exception:
            image_np = np.frombuffer(input_, dtype='>u1')
            image = PIL.Image.fromarray(image_np[None])
        image = image.convert('L')

        # 原始图像张量 [1, 1, 250, 100]
        images = myTransform(image)[None]
        scores = clsf.predict_proba(images)
        labels = scores.argmax(dim=1)

        # 确保 CW 攻击的输入和模型在同一设备上（否则会出现 cuda weight vs cpu input 报错）
        try:
            model_device = next(clsf.model.parameters()).device
        except Exception:
            model_device = torch.device("cpu")

        images_original = images.detach().cpu()  # 仅用于后续 numpy 拼接与 resize
        images = images.to(model_device)
        labels = labels.to(model_device)

        # CW-L2 攻击在 torch.Tensor 上运行
        adverisalExamples = carlini_wagner_l2(clsf.model, images, labels, max_iterations=100)
        adv_scores = clsf.predict_proba(adverisalExamples)
        adv_labels = adv_scores.argmax(dim=1)
        isAdverisalExamples = (adv_labels != labels).detach().cpu().numpy()
        isSuccessAdversialExamples = isAdverisalExamples

        # 将原图与对抗样本在宽度维度拼接，再 resize 回网络输入尺寸
        paddingAEs_np = np.concatenate(
            (images_original.detach().cpu().numpy(), adverisalExamples.detach().cpu().numpy()),
            axis=3  # 宽度方向拼接: [N, C, H, W*2]
        )
        paddingAEs = torch.from_numpy(paddingAEs_np)  # CPU tensor
        paddingAEs = resize(paddingAEs)               # CPU resize

        padding_scores = clsf.predict_proba(paddingAEs)
        padding_labels = padding_scores.argmax(dim=1)
        isExecAEsP = (padding_labels != labels).detach().cpu().numpy()


        self._attack_finish()

        success = bool(isExecAEsP[0])
        if success:
            self._succeed()
        # 与 GammaAttacker 等保持一致的返回接口：(sha256, label)
        return None, success

    def setup_seed(self, seed=0):
        torch.manual_seed(seed)  # 为CPU设置随机种子
        np.random.seed(seed)  # Numpy module.
        random.seed(seed)  # Python random module.
        if torch.cuda.is_available():
            # torch.backends.cudnn.benchmark = False
            torch.backends.cudnn.deterministic = True
            torch.cuda.manual_seed(seed)  # 为当前GPU设置随机种子
            torch.cuda.manual_seed_all(seed)  # 为所有GPU设置随机种子
