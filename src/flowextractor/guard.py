from flowextractor.model import *
import argparse
import pandas
import torch
import tqdm

class FlowGuard:
    def __init__(self, model_path):
        self.model = torch.load(model_path, weights_only=False)

    def get_model(self):
        return self.model

    def predict(self, flow_features):
        with torch.no_grad():
            flow_tensor = torch.tensor(flow_features, dtype=torch.float32)
            output = self.model(flow_tensor)
            prediction = torch.sigmoid(output).item()
            return prediction


def main():
    argparser = argparse.ArgumentParser(description="FlowGuard: A tool for detecting attacks in network flows using a trained neural network model.")
    argparser.add_argument("--model_path", type=str, required=True, help="Path to the trained model file.")
    args = argparser.parse_args()

    flow_guard = FlowGuard(args.model_path)
    print("FlowGuard initialized with model:", args.model_path)

    test_data = pandas.read_csv("flow_vectors.csv")[:100]
    test_data_normalized = normalize_training_data(test_data)
    x_test = test_data_normalized[["Number of Packets (Scaled to 1000000)", "Source Port", "Destination Port", "Average Packet Size", "Minimum Packet Size", "Maximum Packet Size", "Total Bytes", "IAT Min", "IAT Max", "IAT Mean"]].to_numpy()
    
    num_malicious = 0
    num_benign = 0
    
    for x in tqdm.tqdm(x_test):
        prediction = flow_guard.predict(x)
        #print(f"Flow Features: {x}, Prediction: {prediction:.4f}")
        if prediction >= 0.5:
            num_malicious += 1
        else:
            num_benign += 1

    print(f"Number of Malicious Flows: {num_malicious}")
    print(f"Number of Benign Flows: {num_benign}")

if __name__ == "__main__":
    main()