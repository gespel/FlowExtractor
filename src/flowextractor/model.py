import torch

class AttackDetectionNet(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = torch.nn.Sequential(
            torch.nn.Linear(8, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 8),
            torch.nn.ReLU(),
            torch.nn.Linear(8, 1)
        )

    def forward(self, x):
        return self.layers(x)

    def train(self, training_data, epochs=10, learning_rate=0.001):
        optimizer = torch.optim.Adam(self.parameters(), lr=learning_rate)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        for epoch in range(epochs):
            for x, y in training_data:
                optimizer.zero_grad()
                y_pred = self.forward(x)
                loss = loss_fn(y_pred, y)
                loss.backward()
                optimizer.step()
            print(f"Epoch {epoch+1}/{epochs} completed.")
        print("Training finished.")

m = AttackDetectionNet()
print(m)