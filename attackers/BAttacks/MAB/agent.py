from ThirdParty.MAB import Bandit, Sample
from attackers.base import AgentBase

class MABAgent(AgentBase):
    def __init__(self, action_space, n_states, n_actions, bandit: Bandit):
        self.n_states = n_states
        self.n_actions = n_actions
        self.action_space = action_space
        self.bandit = bandit

    def choose_action(self, s: Sample):
        return self.bandit.get_next_arm(s, s.get_applied_actions())