"""Führt dataset_exploration.ipynb für alle Datensätze aus.

dataset_exploration.ipynb selbst ist die SSH-Variante (DATASET = "ssh_bruteforce") und wird in-place ausgeführt;
für die übrigen Datensätze entsteht je eine Kopie dataset_exploration_<name>.ipynb.

    uv run python notebooks/run_all.py [ssh_bruteforce gobuster slowloris]
"""
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import nbformat
from nbconvert.preprocessors import ExecutePreprocessor

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "dataset_exploration.ipynb"
DEFAULT_LINE = 'DATASET = "ssh_bruteforce"'
DATASETS = ["ssh_bruteforce", "gobuster", "slowloris"]


def target(name):
    return TEMPLATE if name == "ssh_bruteforce" else HERE / f"dataset_exploration_{name}.ipynb"


def run(name):
    nb = nbformat.read(TEMPLATE, as_version=4)
    config, intro = nb.cells[1], nb.cells[0]
    assert DEFAULT_LINE in config.source, "DATASET-Zeile in der ersten Code-Zelle nicht gefunden"
    config.source = config.source.replace(DEFAULT_LINE, f'DATASET = "{name}"')
    intro.source = intro.source.replace("`ssh_bruteforce.csv`", f"`{name}.csv`", 1)
    ExecutePreprocessor(timeout=None, kernel_name="python3").preprocess(nb, {"metadata": {"path": str(HERE)}})
    nbformat.write(nb, target(name))
    return target(name)


if __name__ == "__main__":
    names = sys.argv[1:] or DATASETS
    with ProcessPoolExecutor(max_workers=len(names)) as pool:
        for path in pool.map(run, names):
            print(f"geschrieben: {path.relative_to(HERE.parent)}")
