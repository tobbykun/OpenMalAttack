import gym
import numpy as np
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from os import PathLike
from os.path import basename
from pathlib import Path
from typing import Dict, List, TypeVar

from utils.file_handler import calc_sha256, fetch_file
from classifiers.base import Classifier

from ThirdParty.MAB import Arm, Bandit, Sample, SamplesManager, MABRewriter
from ThirdParty.MAB.utils import SAMPLE_STATUS_EVASIVE, SAMPLE_STATUS_MINIMAL, SAMPLE_STATUS_PENDING, SAMPLE_STATUS_SKIP, SAMPLE_STATUS_WORKING, SCAN_STATUS_DELETED, SCAN_STATUS_PASS, SCAN_STATUS_WAITING

@dataclass
class RLHistory:
    actions: List[Arm] = field(default_factory=lambda: [])
    reward: float = 0.0
    output: bool = False
    evaded_path: str = ''

class MABEnv(gym.Env):
  def __init__(self, sha256list: List[PathLike], model: Classifier, random_sample=False, maxturns=100, output_path='data/output/rl/evaded', confidence=True):
    self.bandit = Bandit()
    self.samples_manager = SamplesManager('/null', self.bandit)
    # Initialize samples from sha256list (file paths)
    self.samples_manager.list_sample = [Sample(p) for p in sha256list]
    for sample in self.samples_manager.list_sample:
      sample.status = SAMPLE_STATUS_PENDING
    print(f'MABEnv initialized with {len(self.samples_manager.list_sample)} samples')
    self.model = model
    self.confidence = confidence
    self.clsf_threshold = self.model.clsf_threshold
    if not self.confidence:
        self.clsf_threshold = 1.0
    self.maxturns = maxturns
    self.rewriter = MABRewriter(self.bandit, self.samples_manager)
    self.history :Dict[str, RLHistory] = OrderedDict()
    self.action_space = gym.spaces.Discrete(len(self.bandit.list_arm))
    self.observation_space = gym.spaces.Discrete(1)
    self.benign_count = 0
    self.episode_lengths = []
    self.current_episode_length = 0
    self._sample_index = 0  # sequential eval: next sample to use
    # Arms write to output/rewriter_output/; ensure it exists (create_folders not run in gym eval)
    os.makedirs('output/rewriter_output', exist_ok=True)

  def _scan(self, sample: Sample):
    path = sample.current_exe_path
    try:
        bytez = Path(path).read_bytes()
    except Exception as e:
        print(f'[MABEnv._scan] Failed to read {path}: {e}')
        # Return high score (malware detected) if file read fails
        return 1.0
    if self.model.__name__ == "MalConv":
        # MalConv.predict_prob returns a tensor, need to extract scalar value
        prob_result = self.model.predict_prob(self.model.extract(bytez))
        if hasattr(prob_result, 'item'):
            score = prob_result.item()
        elif isinstance(prob_result, (list, np.ndarray)) and len(prob_result) > 0:
            score = float(prob_result[0])
        else:
            score = float(prob_result)
    elif self.model.__name__ == "MalGraph" or self.model.__name__ == "Magic":
        score = self.model.get_score(bytez, calc_sha256(bytez))
    else:
        raise NotImplementedError

    if score < self.clsf_threshold:
        sample.scan_status = SCAN_STATUS_PASS
    else:
        sample.scan_status = SCAN_STATUS_DELETED
    return score

  def step(self, action: Arm):
    self.turns += 1
    self.current_episode_length += 1
    try:
        output_path = action.pull(self.sample)
        if not Path(output_path).exists():
            print(f'[MABEnv.step] Warning: output_path does not exist: {output_path}')
        self.sample.set_current_exe_path(output_path)
        self.sample.append_arm(action)
        self.score = self._scan(self.sample)
    except Exception as e:
        print(f'[MABEnv.step] Error in action.pull or _scan: {e}')
        import traceback
        traceback.print_exc()
        # Return failure state
        episode_over = True
        if self.sha256 not in self.history:
            self.history[self.sha256] = RLHistory()
        self.history[self.sha256].output = False
        self.history[self.sha256].reward = -1.0
        self.episode_lengths.append(self.current_episode_length)
        return self.sample, -1.0, episode_over, self.history[self.sha256].__dict__
    if self.score < self.clsf_threshold:  # successful evasion
        self.sample.status = SAMPLE_STATUS_EVASIVE
        reward = self.original_result - self.score
        self.history[self.sha256].output = True
        self.history[self.sha256].reward = reward
        self.history[self.sha256].evaded_path = self.sample.current_exe_path
        self.history[self.sha256].actions = self.sample.current_applied_arm_subset
        episode_over = True
        self.sample.scan_status = SCAN_STATUS_PASS
        self.episode_lengths.append(self.current_episode_length)
        # Skip minimize_evasive_sample / update_evasive_list / update_working_list:
        # they use os.system('mv'/'rm') and scan_folder logic; not needed for gym eval.
    elif self.turns >= self.maxturns:
        reward = self.original_result - self.score
        episode_over = True
        self.history[self.sha256].output = False
        self.history[self.sha256].reward = reward
        self.episode_lengths.append(self.current_episode_length)
    else:
        reward = self.original_result - self.score
        episode_over = False
    self.sample.status = SAMPLE_STATUS_WORKING
    # Skip update_working_list: uses mv/rm/check_scan_status; not needed for gym eval.
    return self.sample, reward, episode_over, self.history[self.sha256].__dict__

  def reset(self):
    self.turns = 0
    self.current_episode_length = 0
    # Sequential eval: iterate over list_sample by index. No get_next_sample / PENDING-WORKING.
    n = len(self.samples_manager.list_sample)
    if self._sample_index >= n:
        print(f'[MABEnv.reset] All {n} samples processed, returning None')
        return None, None
    while self._sample_index < n:
        self.sample = self.samples_manager.list_sample[self._sample_index]
        self._sample_index += 1
        self.sample.reset()  # clear applied arms etc. for new episode
        self.sample.status = SAMPLE_STATUS_WORKING
        self.sha256 = basename(self.sample.path)
        self.history[self.sha256] = RLHistory()
        try:
            self.bytez = Path(self.sample.path).read_bytes()
        except Exception as e:
            print(f'[MABEnv.reset] skip {self.sha256}: read_bytes failed: {e}')
            continue
        self.observation_space = self.sample
        if self.model.__name__ == "MalConv":
            prob_result = self.model.predict_prob(self.model.extract(self.bytez))
            if hasattr(prob_result, 'item'):
                self.original_result = prob_result.item()
            elif isinstance(prob_result, (list, np.ndarray)) and len(prob_result) > 0:
                self.original_result = float(prob_result[0])
            else:
                self.original_result = float(prob_result)
        elif self.model.__name__ == "MalGraph" or self.model.__name__ == "Magic":
            self.original_result = self.model.get_score(self.bytez, calc_sha256(self.bytez))
        else:
            raise NotImplementedError
        if self.original_result >= self.clsf_threshold:
            return self.sample, self.sha256
        self.benign_count += 1
    return None, None
  
  def get_episode_lengths(self):
    return self.episode_lengths