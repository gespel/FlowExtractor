import torch
import pandas
import tqdm
import argparse

class SSHAttackDetectionNet(torch.nn.Module):
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

    def train(self, training_data, epochs=20, learning_rate=0.001):
        optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        for epoch in tqdm.tqdm(range(epochs), desc="Training Epochs"):
            total_loss = 0
            for x, y in tqdm.tqdm(training_data, leave=False):
                optimizer.zero_grad()
                y_pred = self.forward(x)
                loss = loss_fn(y_pred, y.unsqueeze(0))
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            tqdm.tqdm.write(f"Epoch {epoch+1}/{epochs} completed. average loss: {total_loss/len(training_data)}")
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
    argparser = argparse.ArgumentParser(description="Train a neural network for attack detection.")
    argparser.add_argument("--feature_csv", type=str, default="flow_vectors.csv", help="Path to the CSV file containing flow features.")
    args = argparser.parse_args()

    training_data = normalize_training_data(pandas.read_csv(args.feature_csv))
    print(training_data.info())

    x_df = training_data[["Number of Packets (Scaled to 1000000)", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]]
    y_df = training_data["Label"]

    x = [xi.tolist() for xi in x_df.to_numpy()]
    y = [1 if i == "malicious" else 0 for i in y_df]

    print(f"{x_df.info()}\n")
    print(y_df.head())

    X_train, X_test = x[:int(len(x)*0.8)], x[int(len(x)*0.8):]
    y_train, y_test = y[:int(len(y)*0.8)], y[int(len(y)*0.8):]

    m = SSHAttackDetectionNet()
    print(m)
    m.train(list(zip([torch.tensor(xi, dtype=torch.float32) for xi in X_train], [torch.tensor(yi, dtype=torch.float32) for yi in y_train])))
    validation_data = list(zip([torch.tensor(xi, dtype=torch.float32) for xi in X_test], [torch.tensor(yi, dtype=torch.float32) for yi in y_test]))
    print(f"Validation data prepared with {len(validation_data)} samples.")
    results = [(x, y, m.forward(x)) for x, y in validation_data]
    for x, y, y_pred in results:
        print(f"True Label: {y} Predicted: {torch.sigmoid(y_pred)}")

    CUTOFF_VALUE = 0.5

    overall = len(results)
    TP = [1 if y == 1 and torch.sigmoid(y_pred) >= CUTOFF_VALUE else 0 for x, y, y_pred in results]
    FP = [1 if y == 0 and torch.sigmoid(y_pred) >= CUTOFF_VALUE else 0 for x, y, y_pred in results]
    TN = [1 if y == 0 and torch.sigmoid(y_pred) < CUTOFF_VALUE else 0 for x, y, y_pred in results]
    FN = [1 if y == 1 and torch.sigmoid(y_pred) < CUTOFF_VALUE else 0 for x, y, y_pred in results]

    print(f"TP: {sum(TP)} ({sum(TP)/overall * 100:.2f} %), FP: {sum(FP)} ({sum(FP)/overall * 100:.2f} %), TN: {sum(TN)} ({sum(TN)/overall * 100:.2f} %), FN: {sum(FN)} ({sum(FN)/overall * 100:.2f} %)")
    print(f"Precision: {sum(TP)/(sum(TP)+sum(FP)) * 100:.2f} %")
    print(f"Recall: {sum(TP)/(sum(TP)+sum(FN)) * 100:.2f} %")
    print(f"F1 Score: {2 * (sum(TP)/(sum(TP)+sum(FP))) * (sum(TP)/(sum(TP)+sum(FN))) / ((sum(TP)/(sum(TP)+sum(FP))) + (sum(TP)/(sum(TP)+sum(FN)))) * 100:.2f} %")
    print(f"False Negatives: {sum(FN)/(sum(FN)+sum(TP)+sum(FP)+sum(TN)) * 100:.2f} %")


if __name__ == "__main__":
    main()

