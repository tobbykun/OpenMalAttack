from dataclasses import dataclass



@dataclass
class TrainParams:
    processed_files_path: str
    # train_test_split_file: str
    max_epochs: int
    train_bs: int
    test_bs: int
    external_func_vocab_file: str
    max_vocab_size: int


@dataclass
class OptimizerParams:
    optimizer_name: str
    lr: float
    weight_decay: float
    momentum: float
    learning_anneal: float
    max_norm: float
    gradient_clip: float


@dataclass
class ModelParams:
    gnn_type: str
    pool_type: str
    acfg_init_dims: int
    cfg_filters: str
    fcg_filters: str
    skip_att_heads: int
    number_classes: int
    dropout_rate: float
    ablation_models: str


@dataclass
class OneEpochResult:
    Epoch_Flag: str
    Number_Samples: int
    Avg_Loss: float
    # ACC: float
    # BalancedACC: float
    Info_100: str
    Info_1000: str
    ROC_AUC_Score: float
    Thresholds: list
    TPRs: list
    FPRs: list
    
    def __str__(self):
        # find_threshold_with_fpr_target(tpr_list=self.TPRs, fpr_list=self.FPRs, threshold_list=self.Thresholds)
        s = "\nResult of \"{}\":\n=Epoch_Flag = {}\n=>Number of samples = {}\n=>Avg_Loss = {}\n=>Info_100 = {}\n=>Info_1000 = {}\n=>ROC_AUC_score = {}\n".format(
            self.Epoch_Flag,
            self.Epoch_Flag,
            self.Number_Samples,
            self.Avg_Loss,
            self.Info_100,
            self.Info_1000,
            self.ROC_AUC_Score)
        return s


if __name__ == '__main__':
    pass
