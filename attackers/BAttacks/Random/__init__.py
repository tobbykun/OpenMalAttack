import random
import time
from dataclasses import dataclass
from pathlib import Path
from classifiers.base import Classifier
from attackers.base import Problem_Space
from utils import manipulate
from utils.file_handler import save_evaded_sample, calc_sha256


@dataclass
class RandomAttackerConfig:
    max_iteration: int = 10
    internal_max_iteration: int = 10
    output_path: Path = Path("output").expanduser()

    def __post_init__(self):
        self.output_path.mkdir(parents=True, exist_ok=True)


class RandomAttacker(Problem_Space):
    """
    对每个PE文件, 最多进行max_iteration*internal_max_iteration次修改,
    外层循环重置PE文件, 内层循环进行具体的修改, 尝试多种方案, 而不是直接累加.
    文件解析失败返回None;
    攻击成功返回最终的sha256值及0,sha256值也是保存的文件名;
    攻击失败返回原始的sha256值及1.
    """

    def __init__(self, **kwargs):
        """
        :param kwargs:
        """
        super(RandomAttacker, self).__init__(**kwargs)
        self.reset()
        self.__name__ = 'Random'
        self.config = RandomAttackerConfig()
        self.config.__dict__.update(kwargs)

    def __call__(self, clsf: Classifier, input_: bytes):
        self._attack_begin()

        for _i in range(self.config.max_iteration):
            print("iteration", _i)
            modified_bytez = input_
            actions = []
            self.action_table = manipulate.ACTION_TABLE.copy()
            for _j in range(self.config.internal_max_iteration):
                action = self._pick_action()
                actions.append(action)
                modified_bytez = self._take_action(modified_bytez, action)
                res = clsf(bytez=modified_bytez)
                if res is False:
                    sha256 = calc_sha256(modified_bytez)
                    save_evaded_sample(self.config.output_path, sha256, modified_bytez)
                    self._attack_finish()
                    self._succeed()
                    return sha256, True
            
        self._attack_finish()
        return None, False  # 攻击失败, 仍然检测为恶意

    def _pick_action(self) -> str:
        """
        pick from action table randomly, cnt--, remove action if cnt=0
        """
        action = random.choice(list(self.action_table.keys()))
        self.action_table[action] -= 1
        if self.action_table[action] == 0:
            del self.action_table[action]
        return action

    def _take_action(self, input_: bytes, action: str) -> bytes:
        """
        执行操作，返回修改后的bytez
        """
        input_ = bytes(manipulate.modify_without_breaking(input_, [action]))
        return input_