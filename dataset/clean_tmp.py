import os
from os import PathLike
from pathlib import Path

class PEDataset():
    def __init__(self, root: PathLike, filt=None):
        '''basic PE dataset

        Args:
            root (str): root abspath of dataset
        '''
        self.root = root
        filt = filt or (lambda x: '.' not in x)
        self.paths = list(Path(root).rglob("*"))
        self.paths = [str(p) for p in self.paths if filt(p.name) and p.is_file()]

    def __getitem__(self, index):
        return self.paths[index]

    def __len__(self):
        return len(self.paths)

path = "./tmp"
for item in PEDataset(str(Path(path).expanduser()))[:]:
    os.system(f"rm {os.path.join(path, item)}")