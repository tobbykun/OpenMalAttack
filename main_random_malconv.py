

from attack_evals.base import Evaler
from attackers import RandomAttacker
from classifiers import MalConv
import json

attacker = RandomAttacker()
clsf = MalConv()
eval_random_malconv = Evaler(attacker=attacker, clsf=clsf)
eval_random_malconv()
