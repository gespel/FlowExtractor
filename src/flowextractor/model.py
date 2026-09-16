import torch
import pandas
import tqdm

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

    def train(self, training_data, epochs=10, learning_rate=0.0001):
        optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        for epoch in range(epochs):
            total_loss = 0
            for x, y in tqdm.tqdm(training_data):
                optimizer.zero_grad()
                y_pred = self.forward(x)
                loss = loss_fn(y_pred, y.unsqueeze(0))
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f"Epoch {epoch+1}/{epochs} completed. average loss: {total_loss/len(training_data)}")
        print("Training finished.")


training_data = pandas.read_csv("big_data_set.csv")
print(training_data.info())

x_df = training_data[["Number of Packets (Scaled to 1000000)", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]]
y_df = training_data["Label"]

x = [xi.tolist() for xi in x_df.to_numpy()]
y = [1 if i == "malicious" else 0 for i in y_df]

print(f"{x_df.info()}\n")
print(y_df.head())

X_train, X_test = x[:int(len(x)*0.8)], x[int(len(x)*0.8):]
y_train, y_test = y[:int(len(y)*0.8)], y[int(len(y)*0.8):]

m = AttackDetectionNet()
print(m)
m.train(list(zip([torch.tensor(xi, dtype=torch.float32) for xi in X_train], [torch.tensor(yi, dtype=torch.float32) for yi in y_train])))
validation_data = list(zip([torch.tensor(xi, dtype=torch.float32) for xi in X_test], [torch.tensor(yi, dtype=torch.float32) for yi in y_test]))
print(f"Validation data prepared with {len(validation_data)} samples.")
results = [(x, y, m.forward(x)) for x, y in validation_data]
for x, y, y_pred in results:
    print(f"True Label: {y} Predicted: {torch.sigmoid(y_pred)}")

CUTOFF_VALUE = 0.5

TP = [1 if y == 1 and torch.sigmoid(y_pred) >= CUTOFF_VALUE else 0 for x, y, y_pred in results]
FP = [1 if y == 0 and torch.sigmoid(y_pred) >= CUTOFF_VALUE else 0 for x, y, y_pred in results]
TN = [1 if y == 0 and torch.sigmoid(y_pred) < CUTOFF_VALUE else 0 for x, y, y_pred in results]
FN = [1 if y == 1 and torch.sigmoid(y_pred) < CUTOFF_VALUE else 0 for x, y, y_pred in results]

print(f"TP: {sum(TP)}, FP: {sum(FP)}, TN: {sum(TN)}, FN: {sum(FN)}")

