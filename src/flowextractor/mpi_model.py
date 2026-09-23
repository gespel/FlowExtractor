import os
import socket
import torch
import torch.distributed as dist
import pandas
import tqdm
import argparse
from mpi4py import MPI
from torch.nn.parallel import DistributedDataParallel
from torch.utils.data import DataLoader
from torch.utils.data.distributed import DistributedSampler

# Start with: mpirun -np <N> python -m flowextractor.mpi_model --feature_csv flow_vectors.csv

def init_distributed(master_port=29500):
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    world_size = comm.Get_size()
    # rank 0 announces its address so all processes can rendezvous, also across nodes
    master_addr = comm.bcast(socket.gethostbyname(socket.gethostname()) if rank == 0 else None, root=0)
    os.environ.setdefault("MASTER_ADDR", master_addr)
    os.environ.setdefault("MASTER_PORT", str(master_port))
    backend = "mpi" if dist.is_mpi_available() else "gloo"
    dist.init_process_group(backend=backend, rank=rank, world_size=world_size)
    return rank, world_size

def is_main_process():
    return dist.get_rank() == 0

class AttackDetectionNet(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = torch.nn.Sequential(
            torch.nn.Linear(10, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 8),
            torch.nn.ReLU(),
            torch.nn.Linear(8, 1)
        )

    def forward(self, x):
        return self.layers(x)

    def train(self, training_data, epochs=200, learning_rate=0.001, batch_size=32):
        # DDP synchronizes the initial weights from rank 0 and averages gradients across all ranks
        ddp_model = DistributedDataParallel(self)
        optimizer = torch.optim.Adam(ddp_model.parameters(), lr=learning_rate)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        sampler = DistributedSampler(training_data, shuffle=True)
        dataloader = DataLoader(training_data, batch_size=batch_size, sampler=sampler)
        for epoch in tqdm.tqdm(range(epochs), desc="Training Epochs", disable=not is_main_process()):
            sampler.set_epoch(epoch)
            total_loss = 0
            for x, y in tqdm.tqdm(dataloader, leave=False, disable=not is_main_process()):
                optimizer.zero_grad()
                y_pred = ddp_model(x)
                loss = loss_fn(y_pred, y.unsqueeze(1))
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            avg_loss = torch.tensor(total_loss / len(dataloader))
            dist.all_reduce(avg_loss, op=dist.ReduceOp.SUM)
            if is_main_process():
                tqdm.tqdm.write(f"Epoch {epoch+1}/{epochs} completed. average loss: {avg_loss.item()/dist.get_world_size()}")
        if is_main_process():
            print("Training finished.")

def normalize_training_data(df):
    feature_columns = ["Number of Packets", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean", "Label", "Attack Type"]
    ndf = df[feature_columns]
    #ndf = ndf.drop(ndf[ndf["Number of Packets"] == 1].index)
    ndf["Number of Packets (Scaled to 1000000)"] = ndf["Number of Packets"] / 1000000
    ndf["Source Port"] = ndf["Source Port"] / 65535
    ndf["Destination Port"] = ndf["Destination Port"] / 65535
    ndf["Average Packet Size"] = ndf["Average Packet Size"] / 1500
    ndf["Minimum Packet Size"] = ndf["Minimum Packet Size"] / 1500
    ndf["Maximum Packet Size"] = ndf["Maximum Packet Size"] / 1500
    ndf["Total Bytes"] = ndf["Total Bytes"] / 150000000
    ndf["IAT Min"] = ndf["IAT Min"] / 60 if ndf["IAT Min"].max() != float('inf') else 0
    ndf["IAT Max"] = ndf["IAT Max"] / 60
    ndf["IAT Mean"] = ndf["IAT Mean"] / 60
    return ndf

def main():
    argparser = argparse.ArgumentParser(description="Train a neural network for attack detection (distributed via MPI).")
    argparser.add_argument("--feature_csv", type=str, default="flow_vectors.csv", help="Path to the CSV file containing flow features.")
    argparser.add_argument("--batch_size", type=int, default=32, help="Batch size used during training (per process).")
    argparser.add_argument("--epochs", type=int, default=20, help="Number of Epochs used for training")
    argparser.add_argument("--master_port", type=int, default=29500, help="Port used by rank 0 for the process group rendezvous.")
    args = argparser.parse_args()

    rank, world_size = init_distributed(args.master_port)
    if is_main_process():
        print(f"Running distributed on {world_size} processes (backend: {dist.get_backend()})")

    training_data = normalize_training_data(pandas.read_csv(args.feature_csv))
    if is_main_process():
        print(training_data.info())

    x_df = training_data[["Number of Packets (Scaled to 1000000)", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]]
    y_df = training_data["Label"]

    x = [xi.tolist() for xi in x_df.to_numpy()]
    y = [1 if i == "malicious" else 0 for i in y_df]

    if is_main_process():
        print(f"{x_df.info()}\n")
        print(y_df.head())

    X_train, X_test = x[:int(len(x)*0.8)], x[int(len(x)*0.8):]
    y_train, y_test = y[:int(len(y)*0.8)], y[int(len(y)*0.8):]

    m = AttackDetectionNet()
    if is_main_process():
        print(m)
    m.train(list(zip([torch.tensor(xi, dtype=torch.float32) for xi in X_train], [torch.tensor(yi, dtype=torch.float32) for yi in y_train])), batch_size=args.batch_size, epochs=args.epochs)
    validation_data = list(zip([torch.tensor(xi, dtype=torch.float32) for xi in X_test], [torch.tensor(yi, dtype=torch.float32) for yi in y_test]))
    if is_main_process():
        print(f"Validation data prepared with {len(validation_data)} samples.")

    # every rank validates its own shard, the counts are summed afterwards
    # (shard indices are strided and padding is off, so no sample is counted twice)
    val_indices = list(range(rank, len(validation_data), world_size))
    dl = DataLoader([validation_data[i] for i in val_indices], batch_size=args.batch_size)
    results = []
    with torch.no_grad():
        for batch in dl:
            x_batch, y_batch = batch
            for x, y in zip(x_batch, y_batch):
                y_pred = m.forward(x)
                results.append((x, y, y_pred))

    #for x, y, y_pred in results:
    #    print(f"True Label: {y} Predicted: {torch.sigmoid(y_pred)}")

    CUTOFF_VALUE = 0.5

    TP = [1 if y == 1 and torch.sigmoid(y_pred) >= CUTOFF_VALUE else 0 for x, y, y_pred in results]
    FP = [1 if y == 0 and torch.sigmoid(y_pred) >= CUTOFF_VALUE else 0 for x, y, y_pred in results]
    TN = [1 if y == 0 and torch.sigmoid(y_pred) < CUTOFF_VALUE else 0 for x, y, y_pred in results]
    FN = [1 if y == 1 and torch.sigmoid(y_pred) < CUTOFF_VALUE else 0 for x, y, y_pred in results]

    counts = torch.tensor([len(results), sum(TP), sum(FP), sum(TN), sum(FN)], dtype=torch.int64)
    dist.all_reduce(counts, op=dist.ReduceOp.SUM)
    overall, TP, FP, TN, FN = counts.tolist()

    if not is_main_process():
        dist.destroy_process_group()
        return

    if overall == 0:
        print("No validation data available.")
        dist.destroy_process_group()
        return
    print(f"TP: {TP} ({TP/overall * 100:.2f} %), FP: {FP} ({FP/overall * 100:.2f} %), TN: {TN} ({TN/overall * 100:.2f} %), FN: {FN} ({FN/overall * 100:.2f} %)")
    if TP+FP == 0:
        print("Precision: N/A (No positive predictions)")
    else:
        print(f"Precision: {TP/(TP+FP) * 100:.2f} %")
    if TP+FN == 0:
        print("Recall: N/A (No actual positives)")
    else:
        print(f"Recall: {TP/(TP+FN) * 100:.2f} %")
    if TP+FP == 0 or TP+FN == 0:
        print("F1 Score: N/A (Cannot compute F1 score)")
    else:
        print(f"F1 Score: {2 * (TP/(TP+FP)) * (TP/(TP+FN)) / ((TP/(TP+FP)) + (TP/(TP+FN))) * 100:.2f} %")
    print(f"False Negatives: {FN/(FN+TP+FP+TN) * 100:.2f} %")
    dist.destroy_process_group()


if __name__ == "__main__":
    main()
