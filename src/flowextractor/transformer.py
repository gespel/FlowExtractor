import copy
import math
import argparse
import pandas
import tqdm
import torch
import matplotlib.pyplot as plt
from flowextractor.model import *

QMAX = {
    torch.int8: 127, 
    torch.int16: 32767, 
    torch.int32: 2**27 - 1
}
COLORS = {
    "float32": "#0004ff", 
    "int32": "#ff0000", 
    "int16": "#00ff00", 
    "int8": "#00eeff"
}

class IntegerLinear(torch.nn.Module):
    def __init__(self, linear, dtype, input_scale, output_max):
        super().__init__()
        self.qmax = QMAX[dtype]
        self.dtype = dtype

        weight_scale = self.qmax / linear.weight.abs().max().item()

        divisor = math.ceil(input_scale * weight_scale * output_max / self.qmax)
        self.output_scale = input_scale * weight_scale / divisor

        self.register_buffer("weight_q", torch.round(linear.weight.detach() * weight_scale).to(dtype))
        self.register_buffer("bias_q", torch.round(linear.bias.detach() * self.output_scale).clamp(-self.qmax, self.qmax).to(dtype))
        self.register_buffer("divisor", torch.tensor(divisor, dtype=torch.int64))

    def forward(self, x):
        x = x.to(torch.int64)
        weight = self.weight_q.to(torch.int64)
        out_features, in_features = weight.shape

        accumulator = torch.zeros(x.shape[:-1] + (out_features,), dtype=torch.int64)
        for o in range(out_features):
            for i in range(in_features):
                accumulator[..., o] += x[..., i] * weight[o, i]

        out = accumulator // self.divisor + self.bias_q
        return out.clamp(-self.qmax, self.qmax).to(self.dtype)


class ModelTransformer:
    def transform(self, model, dtype, calibration_data):
        quantized_model = copy.deepcopy(model)
        quantized_model.dtype = dtype
        quantized_model.input_scale = QMAX[dtype] / calibration_data.abs().max().item()

        with torch.no_grad():
            scale = quantized_model.input_scale
            x = calibration_data
            for i in range(len(model.layers)):
                x = model.layers[i](x)
                if isinstance(model.layers[i], torch.nn.Linear):
                    quantized_model.layers[i] = IntegerLinear(model.layers[i], dtype, scale, x.abs().max().item())
                    scale = quantized_model.layers[i].output_scale
        return quantized_model

    def transform_to_int8(self, model, calibration_data):
        return self.transform(model, torch.int8, calibration_data)

    def transform_to_int16(self, model, calibration_data):
        return self.transform(model, torch.int16, calibration_data)

    def transform_to_int32(self, model, calibration_data):
        return self.transform(model, torch.int32, calibration_data)


def quantize_input(quantized_model, x):
    qmax = QMAX[quantized_model.dtype]
    return torch.round(x * quantized_model.input_scale).clamp(-qmax, qmax).to(quantized_model.dtype)


def evaluate(model, x, y, float_prediction):
    with torch.no_grad():
        if hasattr(model, "input_scale"):
            prediction = (model(quantize_input(model, x)) > 0).squeeze(1)
        else:
            prediction = (model(x) > 0).squeeze(1)

    tp = (prediction & y).sum().item()
    fp = (prediction & ~y).sum().item()
    fn = (~prediction & y).sum().item()
    tn = (~prediction & ~y).sum().item()
    precision = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0

    return {
        "Accuracy": (tp + tn) / len(y),
        "Precision": precision,
        "Recall": recall,
        "F1": 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0,
        "Agreement\nwith float32": (prediction == float_prediction).float().mean().item(),
        "FN rate\n(missed attacks)": fn / (tp + fn) if tp + fn > 0 else 0,
        "FP rate\n(false alarms)": fp / (fp + tn) if fp + tn > 0 else 0,
    }


def plot_comparison(model, x, y, plot_path):
    split = int(len(x) * 0.8)
    x_train, x_test, y_test = x[:split], x[split:], y[split:]

    models = {"float32": model}
    for name in ["int32", "int16", "int8"]:
        models[name] = ModelTransformer().transform(model, getattr(torch, name), x_train)

    with torch.no_grad():
        float_prediction = (model(x_test) > 0).squeeze(1)
    results = {}
    for name in models:
        results[name] = evaluate(models[name], x_test, y_test, float_prediction)
        print(name, ", ".join(f"{metric.split(chr(10))[0]}: {value * 100:.2f} %" for metric, value in results[name].items()))

    metrics = list(results["float32"])
    fig, (ax_left, ax_right) = plt.subplots(1, 2, figsize=(14, 5.2), gridspec_kw={"width_ratios": [5, 2.2]})
    for axis, axis_metrics in [(ax_left, metrics[:5]), (ax_right, metrics[5:])]:
        width = 0.2
        for i, name in enumerate(results):
            positions = [m + (i - 1.5) * width for m in range(len(axis_metrics))]
            values = [results[name][metric] * 100 for metric in axis_metrics]
            axis.bar(positions, values, width * 0.92, color=COLORS[name], label=name)
            for position, value in zip(positions, values):
                axis.text(position, value, f" {value:.2f}", ha="center", va="bottom", fontsize=7, rotation=90, color="#52514e")
        axis.set_xticks(range(len(axis_metrics)), axis_metrics)
        axis.set_ylabel("%")
        axis.spines[["top", "right"]].set_visible(False)
        axis.grid(axis="y", color="#e5e4df", linewidth=0.8)
        axis.set_axisbelow(True)

    highest_error_rate = max(results[name][metric] for name in results for metric in metrics[5:]) * 100
    ax_left.set_ylim(0, 115)
    ax_right.set_ylim(0, highest_error_rate * 1.3 if highest_error_rate > 0 else 1)
    ax_left.set_title(f"Classification on the validation split ({len(x_test):,} flows)", loc="left")
    ax_right.set_title("Error rates (lower is better)", loc="left")
    ax_left.legend(ncol=4, frameon=False, loc="upper left", bbox_to_anchor=(0, -0.13))
    fig.tight_layout()
    fig.savefig(plot_path, dpi=150)
    print(f"plot saved to {plot_path}")


def main():
    argparser = argparse.ArgumentParser(description="Quantize a trained AttackDetectionNet to a pure integer model.")
    argparser.add_argument("--model_path", type=str, required=True)
    argparser.add_argument("--dtype", type=str, choices=["int8", "int16", "int32"], required=True)
    argparser.add_argument("--output_path", type=str, required=True)
    argparser.add_argument("--feature_csv", type=str, default="flow_vectors.csv")
    argparser.add_argument("--plot", type=str, help="Compares float32, int32, int16 and int8 on the validation split and saves the plot to this path.")
    args = argparser.parse_args()

    model = torch.load(args.model_path, weights_only=False)

    df = normalize_training_data(pandas.read_csv(args.feature_csv))
    x = torch.tensor(df[FEATURE_COLUMNS].to_numpy(), dtype=torch.float32)

    mt = ModelTransformer()

    quantized_model = mt.transform(model, getattr(torch, args.dtype), x)
    print(quantized_model)

    torch.save(quantized_model, args.output_path)

    if args.plot:
        y = torch.tensor((df["Label"] == "malicious").to_numpy())
        plot_comparison(model, x, y, args.plot)


if __name__ == "__main__":
    main()
