from typing import Iterable
from attackers.base import Attacker, Problem_Space, Feature_Space, RLAttacker
from classifiers.base import Classifier
from tqdm import tqdm
from dataset import malware_data
import logging
from datetime import datetime

class Evaler:
    """
    Base class for ML/DL attackers.
    """
    def __init__(self, attacker : Attacker, clsf : Classifier):
        """
        benign:     Count the number of software classified as benign originally.
        success:    Count the number of malware evading classifier successfully.
        failure:    Count the number of malware not evading classifier.
        error:      Count the number of software raising error.
        """
        assert isinstance(attacker, Problem_Space) or isinstance(attacker, Feature_Space) or isinstance(attacker, RLAttacker)
        self.attacker = attacker
        self.clsf = clsf

        logging.basicConfig(filename=f"logs/eval/{datetime.now().strftime('%Y-%m-%d_%H:%M:%S_%f')}", 
                                        filemode="a+", 
                                        format="%(asctime)s %(name)s:%(levelname)s:%(message)s", 
                                        datefmt="%d-%M-%Y %H:%M:%S", 
                                        level=logging.INFO)

    def __call__(self, dataset=malware_data, change_input=0):
        """
        evaluate the attacker against classifier.
        Param:
            change_input: set to 1 if the attacker is malfox. note that it is used only for malfox. 
        return True if Attack succeeded, return False otherwise.
        """
        logging.info(f"[Evalation] {self.attacker.__name__}->{self.clsf.__name__}")
        print(f"[Evalation] {self.attacker.__name__}->{self.clsf.__name__}")
        # with tqdm(total=len(dataset), desc="Evaluation") as pbar:
        for i, data in enumerate(dataset):
            if self.attacker.__name__ != "MalFox":
                if isinstance(data, str):  # if data is path
                    data = open(data, 'rb').read()
                if not self.clsf(data).item():
                    continue

            sha256, label = self.attacker(self.clsf, data)
            print(i, sha256, label)

        print("ASR: {}".format(self.attacker._ASR()))
        print("Time Consuming: {}".format(self.attacker._Mean_Time()))

class RLEvaler:
    """
    Base class for evaluting RL attackers.
    """
    def __init__(self, attacker : RLAttacker, clsf : Classifier):
        """
        benign:     Count the number of software classified as benign originally.
        success:    Count the number of malware evading classifier successfully.
        failure:    Count the number of malware not evading classifier.
        error:      Count the number of software raising error.
        """
        assert isinstance(attacker, RLAttacker)
        self.attacker = attacker
        self.clsf = clsf

        logging.basicConfig(filename=f"logs/eval/{datetime.now().strftime('%Y-%m-%d_%H:%M:%S_%f')}", 
                                        filemode="a+", 
                                        format="%(asctime)s %(name)s:%(levelname)s:%(message)s", 
                                        datefmt="%d-%M-%Y %H:%M:%S", 
                                        level=logging.INFO)

    def __call__(self, env_id, dataset=malware_data, training=False):
        """
        evaluate the attacker against classifier.
        return True if Attack succeeded, return False otherwise.
        """
        logging.info(f"[Evalation] {self.attacker.__name__}->{self.clsf.__name__}")
        print(f"[Evalation] {self.attacker.__name__}->{self.clsf.__name__}")
        try:
            with tqdm(total=len(dataset), desc="Evaluation") as pbar:
                self.attacker(clsf=self.clsf,
                                training=training,
                                id=env_id,
                                sha256list=dataset,
                                pbar=pbar)
        except Exception as e:
            logging.exception(e)
            print(f"ERROR in evaluation: {e}")
            import traceback
            traceback.print_exc()
        
        print("ASR: {}".format(self.attacker._ASR()))
        print("Time Consuming: {}".format(self.attacker._Mean_Time()))
