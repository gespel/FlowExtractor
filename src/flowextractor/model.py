import torch
import pandas

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

    def train(self, training_data, epochs=100, learning_rate=0.001):
        optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        for epoch in range(epochs):
            total_loss = 0
            for x, y in training_data:
                optimizer.zero_grad()
                y_pred = self.forward(x)
                loss = loss_fn(y_pred, y.unsqueeze(0))
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f"Epoch {epoch+1}/{epochs} completed. average loss: {total_loss/len(training_data)}")
        print("Training finished.")

training_data = pandas.read_csv("flow_vectors.csv")
print(training_data.info())

x_df = training_data[["Number of Packets (Scaled to 1000000)", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]]
y_df = training_data["Label"]

x = []
y = []
for i in range(len(y_df)):
    if y_df[i] != "benign" and y_df[i] != "malicious":
        y_df[i] = "benign"
    if y_df[i] == "benign":
        y_df[i] = "benign"
    if y_df[i] == "malicious":
        y_df[i] = "malicious"
    if y_df[i] == "benign":
        y.append(0)
    if y_df[i] == "malicious":
        y.append(1)

for i in range(len(x_df)):
    x.append(x_df.iloc[i].tolist())

print(f"{x_df.info()}\n")
print(y_df.head())

training_data = []
for i in range(len(x)):
    training_data.append((torch.tensor(x[i], dtype=torch.float32), torch.tensor(y[i], dtype=torch.float32)))

m = AttackDetectionNet()
print(m)
m.train(training_data)