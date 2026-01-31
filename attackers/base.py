from gym.envs.registration import register
from utils.file_handler import get_rl_dataset
import time
# 模型直接导入。
# 攻击提供接口，可以直接获取对抗样本攻击结果。

class Attacker:
    """
    This is the base class for attackers.
    """
    
    def __init__(self, 
                 total_time=.0, 
                 att_cnt=0, 
                 att_succ=0,
                 timer=0,
                 **kwargs):
        """
        total_time: Sum of Attack time-consuming.
        att_cnt:    Count of Attacks.
        att_succ:   Count of Succeeded Attacks.
        """
        self.total_time = total_time
        self.att_cnt = att_cnt
        self.att_succ = att_succ
        self.timer = timer
        self.kwargs = kwargs

    @property
    def name(self):
        return self.__class__.__name__
    
    def reset(self):
        """
        Reset the statistic variables.
        """
        self.total_time = .0
        self.att_cnt = 0
        self.att_succ = 0
        self.timer = .0
    
    def _cntIncrese(self):
        """
        If an attack is performed, the count(att_cnt) is incremented by one.
        """
        self.att_cnt += self.batchsize

    def _succeed(self, n=1):
        """
        If an attack is successful, the count(att_succ) is incremented by one.
        """
        self.att_succ += n

    def _attack_begin(self, batchsize=1):
        """
        Record the time of the start of an attack.
        """
        self.batchsize = batchsize
        self._cntIncrese()
        self.timer = time.time()

    def _attack_finish(self):
        """
        Record the time of the end of an attack and count the time spent.
        """
        if hasattr(self, 'batchsize') and self.batchsize > 0:
            self.total_time += (time.time() - self.timer)/self.batchsize
        self.timer = .0

    def _ASR(self):
        """
        return(Float): Attack success rate.
        """
        if self.att_cnt == 0:
            return 0.0
        return self.att_succ/self.att_cnt
    
    def _Mean_Time(self):
        """
        return(Float): Average time-consuming.
        """
        if self.att_cnt == 0:
            return 0.0
        return self.total_time/self.att_cnt

class Problem_Space(Attacker):
    def __init__(self, **kwargs):
        super(Problem_Space, self).__init__(**kwargs)

    def __call__(self, clsf, input_):
        """
        return(sha256, bytes, label): 
            sha256: sha256 of bytes. 
            bytes:  bytes of the smanipulated malware if attack succeeded, 
                    otherwise bytes of the original malware. 
            label:  True if attack succeeded, otherwise False. 
        """
        raise NotImplementedError()

class Feature_Space(Attacker):
    def __init__(self, **kwargs):
        super(Feature_Space, self).__init__(**kwargs)

    def __call__(self, clsf, input_):
        """
        return(file, label): 
            file:   Path of the malware.
            label:  True if attack succeeded, otherwise False.
        """
        raise NotImplementedError()
    
class AgentBase:
    """
    Base class for Agent.
    """
    def __init__(self, **kwargs):
        pass

    def choose_action(self, *args):
        """
        Choose action
        """
        raise NotImplementedError()

class RLAttacker(Attacker):
    """
    Base class for RL attackers using gym.
    """
    def __init__(self, **kwargs):
        super(RLAttacker, self).__init__(**kwargs)

    def __call__(self, 
                 clsf, 
                 training,
                 *args):
        """
        :param clsf(classifier):    The detector to be attacked.
        :param training(bool):      indicating whether to run the attacker in training mode or inference mode.
        """
        raise NotImplementedError()
    
    def train(self):
        pass
    
    def eval(self):
        raise NotImplementedError()
    
    def register_env(self, clsf, id, entry_point, random_sample, maxturns, sha256list, confidence):
        register(
            id=id,
            entry_point=entry_point,
            kwargs={
                'random_sample': random_sample,
                'maxturns': maxturns,
                'sha256list': sha256list,
                'model': clsf,
                'confidence': confidence
            }
        )