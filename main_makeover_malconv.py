
from attack_evals.base import Evaler
from attackers import MakeOverAttacker
from classifiers import MalConv


if __name__ == "__main__":
    attacker = MakeOverAttacker()
    clsf = MalConv()
    eval_makeover_malconv = Evaler(attacker=attacker, clsf=clsf)
    eval_makeover_malconv()