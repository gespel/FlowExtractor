import copy
import math
import argparse
import pandas
import torch
from flowextractor.model import *

QMAX = {torch.int8: 127, torch.int16: 32767, torch.int32: 2**27 - 1}


def find_shift(max_abs_value, qmax):
    return math.floor(math.log2(qmax / max_abs_value)) if max_abs_value > 0 else 0


class IntegerLinear(torch.nn.Module):
    def __init__(self, linear, dtype, input_shift, output_shift):
        super().__init__()
        self.qmax = QMAX[dtype]
        self.dtype = dtype
        out_features = linear.out_features
        self.register_buffer("weight_q", torch.zeros(out_features, linear.in_features, dtype=dtype))
        self.register_buffer("bias_q", torch.zeros(out_features, dtype=dtype))
        self.register_buffer("shift", torch.zeros(out_features, dtype=dtype))

        weight_shifts = [find_shift(linear.weight[row].abs().max().item(), self.qmax) for row in range(out_features)]
        output_shift = min(output_shift, input_shift + min(weight_shifts))
        self.output_shift = output_shift

        for row in range(out_features):
            self.weight_q[row] = torch.round(linear.weight[row].detach() * 2**weight_shifts[row])
            self.bias_q[row] = max(-self.qmax, min(self.qmax, round(linear.bias[row].item() * 2**output_shift)))
            self.shift[row] = input_shift + weight_shifts[row] - output_shift

    def forward(self, x):
        out = (x.long() @ self.weight_q.long().T >> self.shift.long()) + self.bias_q
        return out.clamp(-self.qmax, self.qmax).to(self.dtype)


class ModelTransformer:
    def transform(self, model, dtype, calibration_data):
        qmax = QMAX[dtype]
        quantized_model = copy.deepcopy(model)
        quantized_model.dtype = dtype

        quantized_model.input_shift = find_shift(calibration_data.abs().max().item(), qmax)
        with torch.no_grad():
            shift = quantized_model.input_shift
            x = calibration_data
            for i in range(len(model.layers)):
                x = model.layers[i](x)
                if isinstance(model.layers[i], torch.nn.Linear):
                    output_shift = find_shift(x.abs().max().item(), qmax)
                    quantized_model.layers[i] = IntegerLinear(quantized_model.layers[i], dtype, shift, output_shift)
                    shift = quantized_model.layers[i].output_shift
        return quantized_model

    def transform_to_int8(self, model, calibration_data):
        return self.transform(model, torch.int8, calibration_data)

    def transform_to_int16(self, model, calibration_data):
        return self.transform(model, torch.int16, calibration_data)

    def transform_to_int32(self, model, calibration_data):
        return self.transform(model, torch.int32, calibration_data)


def quantize_input(quantized_model, x):
    qmax = QMAX[quantized_model.dtype]
    return torch.round(x * 2**quantized_model.input_shift).clamp(-qmax, qmax).to(quantized_model.dtype)


def main():
    argparser = argparse.ArgumentParser(description="Quantize a trained AttackDetectionNet to a pure integer model.")
    argparser.add_argument("--model_path", type=str, required=True)
    argparser.add_argument("--dtype", type=str, choices=["int8", "int16", "int32"], required=True)
    argparser.add_argument("--output_path", type=str, required=True)
    argparser.add_argument("--feature_csv", type=str, default="flow_vectors.csv")
    args = argparser.parse_args()

    model = torch.load(args.model_path, weights_only=False)
    df = normalize_training_data(pandas.read_csv(args.feature_csv))
    x = torch.tensor(df[FEATURE_COLUMNS].to_numpy(), dtype=torch.float32)
    quantized_model = ModelTransformer().transform(model, getattr(torch, args.dtype), x)

    with torch.no_grad():
        agreement = ((model(x) > 0) == (quantized_model(quantize_input(quantized_model, x)) > 0)).float().mean().item()
    print(f"agreement with float model: {agreement * 100:.2f} %")
    torch.save(quantized_model, args.output_path)


if __name__ == "__main__":
    main()
