import torch
import numpy
import pandas
import tqdm
import argparse
import time
from torch.utils.data import DataLoader

FEATURE_COLUMNS = ["Number of Packets", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]
LOG_SCALED_COLUMNS = ["Number of Packets", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]

class AttackDetectionNet(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = torch.nn.Sequential(
            torch.nn.Linear(10, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 8),
            torch.nn.ReLU(),
            torch.nn.Linear(8, 1)
        )

    def forward(self, x):
        return self.layers(x)

    def fit(self, training_data, epochs=200, learning_rate=0.001, batch_size=32):
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Training on {device}.")
        self.to(device)
        self.train()
        optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        dataloader = DataLoader(training_data, batch_size=batch_size, shuffle=True)
        for epoch in tqdm.tqdm(range(epochs), desc="Training Epochs"):
            total_loss = 0
            for x, y in tqdm.tqdm(dataloader, leave=False):
                x, y = x.to(device), y.to(device)
                optimizer.zero_grad()
                y_pred = self.forward(x)
                loss = loss_fn(y_pred, y.unsqueeze(1))
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            tqdm.tqdm.write(f"Epoch {epoch+1}/{epochs} completed. average loss: {total_loss/len(dataloader)}")
        self.to("cpu")
        self.eval()
        print("Training finished.")

def print_metrics(name, y_true, y_pred):
    TP = int(((y_true == 1) & (y_pred == 1)).sum())
    FP = int(((y_true == 0) & (y_pred == 1)).sum())
    TN = int(((y_true == 0) & (y_pred == 0)).sum())
    FN = int(((y_true == 1) & (y_pred == 0)).sum())
    overall = TP + FP + TN + FN
    print(f"-> {name} ({overall} samples)")
    if overall == 0:
        print("No validation data available.")
        return
    print(f"TP: {TP} ({TP/overall * 100:.2f} %), FP: {FP} ({FP/overall * 100:.2f} %), TN: {TN} ({TN/overall * 100:.2f} %), FN: {FN} ({FN/overall * 100:.2f} %)")
    precision = TP / (TP + FP) if TP + FP > 0 else None
    recall = TP / (TP + FN) if TP + FN > 0 else None
    print(f"Precision: {precision * 100:.2f} %" if precision is not None else "Precision: N/A (No positive predictions)")
    print(f"Recall: {recall * 100:.2f} %" if recall is not None else "Recall: N/A (No actual positives)")
    if not precision or not recall:
        print("F1 Score: N/A (Cannot compute F1 score)")
    else:
        print(f"F1 Score: {2 * precision * recall / (precision + recall) * 100:.2f} %")

def normalize_training_data(df):
    ndf = df[FEATURE_COLUMNS + ["Label", "Attack Type"]].copy()
    ndf = ndf.replace(float("inf"), 0)
    for column in ["IAT Min", "IAT Max", "IAT Mean"]:
        ndf[column] = ndf[column] * 1000000
    for column in LOG_SCALED_COLUMNS:
        ndf[column] = numpy.log2(1 + ndf[column]) / 32
    ndf["Source Port"] = ndf["Source Port"] / 65535
    ndf["Destination Port"] = ndf["Destination Port"] / 65535
    return ndf

def main():
    argparser = argparse.ArgumentParser(description="Train a neural network for attack detection.")
    argparser.add_argument("--feature_csv", type=str, default="flow_vectors.csv", help="Path to the CSV file containing flow features.")
    argparser.add_argument("--batch_size", type=int, default=32, help="Batch size used during training.")
    argparser.add_argument("--epochs", type=int, default=20, help="Number of Epochs used for training")
    argparser.add_argument("--dry_run", action="store_true", help="If set, the script will train the model but will not save it.")
    argparser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible training.")
    args = argparser.parse_args()

    if args.seed is not None:
        torch.manual_seed(args.seed)

    raw_data = pandas.read_csv(args.feature_csv)
    training_data = normalize_training_data(raw_data)
    print(training_data.info())

    x = torch.tensor(training_data[FEATURE_COLUMNS].to_numpy(), dtype=torch.float32)
    y = torch.tensor((training_data["Label"] == "malicious").to_numpy(), dtype=torch.float32)
    is_ssh = torch.tensor(((raw_data["Source Port"] == 22) | (raw_data["Destination Port"] == 22)).to_numpy())

    # chronological split: flows are appended to the csv in recording order
    split = int(len(x) * 0.8)
    X_train, X_test = x[:split], x[split:]
    y_train, y_test = y[:split], y[split:]
    ssh_test = is_ssh[split:]
    print(f"Train: {len(y_train)} samples ({int(y_train.sum())} malicious), Test: {len(y_test)} samples ({int(y_test.sum())} malicious)")

    m = AttackDetectionNet()
    print(m)
    m.fit(list(zip(X_train, y_train)), batch_size=args.batch_size, epochs=args.epochs)

    if not args.dry_run:
        torch.save(m, f"{time.strftime('%Y%m%d-%H%M%S')}.pt")

    CUTOFF_VALUE = 0.5

    with torch.no_grad():
        y_pred = (torch.sigmoid(m(X_test).squeeze(1)) >= CUTOFF_VALUE).int()
    y_true = y_test.int()

    print_metrics("All flows", y_true, y_pred)
    print_metrics("SSH flows only", y_true[ssh_test], y_pred[ssh_test])
    print_metrics("Baseline: port 22 => malicious", y_true, ssh_test.int())


if __name__ == "__main__":
    main()

