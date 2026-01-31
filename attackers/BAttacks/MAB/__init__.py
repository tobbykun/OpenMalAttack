import gym
import numpy as np
import time
from attackers.BAttacks.MAB.agent import MABAgent
from attackers.base import RLAttacker
from tqdm import tqdm

class MABAttacker(RLAttacker):
    def __init__(self, log_dir = 'logs/mab.log', **kwargs):
        super(MABAttacker, self).__init__(**kwargs)
        self.reset()
        self.agent = MABAgent
        self.log_dir = log_dir
        self.entry_point = 'attackers.BAttacks.MAB.env:MABEnv'

        self.__name__ = 'MAB'

    def __call__(self, 
                 clsf, 
                 id: str,
                 sha256list: list,
                 pbar: tqdm,
                 random_sample=False,
                 maxturns=10,
                 confidence=True,
                 **kwargs):  # Accept training and other kwargs to match RLEvaler call
        self.register_env(clsf, id, self.entry_point, random_sample, maxturns, sha256list, confidence)
        self.test_model_env = gym.make(id)
        # Skip RecordVideo wrapper - it can hide .bandit/.benign_count; not needed for eval
        self.test_episode_count = len(sha256list)
        return self.eval(pbar)

    def eval(self, pbar):
        """test with model"""
        done = False
        reward = 0
        test_model_evasions = 0
        evasion_history = {}
        ep_history = {}  # Initialize to avoid NameError if loop exits early
        
        # Ensure _attack_begin is called before anything else to initialize att_cnt
        if self.test_episode_count > 0:
            self._attack_begin(self.test_episode_count)
        else:
            # If no episodes, still initialize counters
            self._attack_begin(1)
        
        try:
            # MABEnv.observation_space is Discrete(1), so n_states should be 1
            # MABAgent needs bandit from the environment
            test_model_agent = self.agent(self.test_model_env.action_space, 1,
                                          self.test_model_env.action_space.n,
                                          self.test_model_env.bandit)

            for test_iter in range(1, self.test_episode_count + 1):
                ob, sha256 = self.test_model_env.reset()
                if ob is None or sha256 is None:
                    # No more samples available
                    print(f'[MABAttacker.eval] No more samples at iteration {test_iter}')
                    break
                
                print(f'[MABAttacker.eval] Starting episode {test_iter}/{self.test_episode_count} for {sha256}')
                while True:
                    # MABAgent.choose_action only needs Sample object
                    action = test_model_agent.choose_action(ob)
                    try:
                        ob_, reward, done, ep_history = self.test_model_env.step(action)
                    except Exception as e:
                        print(f'[MABAttacker.eval] Exception in step(): {e}')
                        import traceback
                        traceback.print_exc()
                        # Create a failure ep_history
                        ep_history = {'output': False, 'reward': -1.0, 'actions': []}
                        done = True
                        reward = -1.0

                    if done:
                        if ep_history.get('output', False):
                            test_model_evasions += 1
                            evasion_history[sha256] = ep_history
                            print("test", test_iter, "/", self.test_episode_count, sha256, "succeed, reward is ", reward, "actions are",
                                  ep_history.get('actions', []))
                            self._succeed()
                        else:
                            print("test", test_iter, "/", self.test_episode_count, sha256, "failed, reward is", reward)
                        break
                    ob = ob_

                pbar.set_postfix(label=(not ep_history.get('output', False)))
                pbar.update()

        finally:
            # Ensure _attack_finish is always called
            if hasattr(self, 'batchsize') and self.batchsize > 0:
                self._attack_finish()

        print('test result with model...')
        print(test_model_evasions, self.test_model_env.benign_count, self.test_episode_count)
        n_mal = self.test_episode_count - self.test_model_env.benign_count
        evasion_rate = (test_model_evasions / n_mal * 100) if n_mal else 0.0
        lens = self.test_model_env.get_episode_lengths()
        mean_action_count = float(np.mean(lens)) if lens else 0.0
        print(f"{evasion_rate}% samples evaded model.")
        print(f"Average of {mean_action_count} moves to evade model.")