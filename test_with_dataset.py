import os
import sys
import argparse
import pandas as pd
import numpy as np

# Ensure root directory in sys.path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.evaluation_service import EvaluationService

def run_cli_evaluation(dataset_path=None):
    # Resolve default path if not specified
    if not dataset_path:
        dataset_path = EvaluationService.get_evaluation_dataset_path()

    if not dataset_path or not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at '{dataset_path}'.")
        sys.exit(1)

    # Execute dynamic evaluation
    res = EvaluationService.run_evaluation(dataset_path=dataset_path, force_refresh=True)

    cm = res["confusion_matrix"]
    classes = res["classes"]
    clf_rep = res["classification_report"]
    ds = res["dataset_analysis"]

    print("=========================================================")
    print("THREATLENS MODEL EVALUATION")
    print("=========================================================")
    print(f"Dataset:               {res['dataset_name']}")
    print(f"Model:                 {res['model_name']} ({res.get('model_version', 'v1.4.2')})")
    print(f"Samples:               {res['total_samples']:,}")
    print(f"Accuracy:              {res['accuracy']:.2f}%")
    print(f"Precision:             {res['precision']:.2f}%")
    print(f"Recall:                {res['recall']:.2f}%")
    print(f"F1 Score:              {res['f1_score']:.2f}%")
    print(f"Correct Predictions:   {res['correct_predictions']:,}")
    print(f"Incorrect Predictions: {res['incorrect_predictions']:,}")
    print("=========================================================")
    print("CONFUSION MATRIX")
    print("=========================================================")
    title_col = "Actual \\ Pred"
    header_col = f"{title_col:<15}" + "".join([f"{c:>12}" for c in classes])
    print(header_col)
    print("-" * len(header_col))
    for i, actual_cls in enumerate(classes):
        row_str = f"{actual_cls:<15}"
        for j in range(len(classes)):
            val = cm[i][j] if i < len(cm) and j < len(cm[i]) else 0
            row_str += f"{val:>12}"
        print(row_str)
    print("=========================================================")
    print("CLASSIFICATION REPORT")
    print("=========================================================")
    report_header = f"{'Class':<18}{'Precision':>12}{'Recall':>12}{'F1-Score':>12}{'Support':>12}"
    print(report_header)
    print("-" * len(report_header))
    for cls in classes:
        if cls in clf_rep:
            metrics = clf_rep[cls]
            prec = f"{metrics.get('precision', 0) * 100:.2f}%"
            rec = f"{metrics.get('recall', 0) * 100:.2f}%"
            f1 = f"{metrics.get('f1-score', 0) * 100:.2f}%"
            sup = str(int(metrics.get('support', 0)))
            print(f"{cls:<18}{prec:>12}{rec:>12}{f1:>12}{sup:>12}")
    if "macro avg" in clf_rep:
        m = clf_rep["macro avg"]
        print("-" * len(report_header))
        print(f"{'Macro Avg':<18}{m.get('precision', 0) * 100:>11.2f}%{m.get('recall', 0) * 100:>11.2f}%{m.get('f1-score', 0) * 100:>11.2f}%{int(m.get('support', 0)):>12}")
    if "weighted avg" in clf_rep:
        w = clf_rep["weighted avg"]
        print(f"{'Weighted Avg':<18}{w.get('precision', 0) * 100:>11.2f}%{w.get('recall', 0) * 100:>11.2f}%{w.get('f1-score', 0) * 100:>11.2f}%{int(w.get('support', 0)):>12}")
    print("=========================================================")
    print("DATASET ANALYSIS")
    print("=========================================================")
    print(f"Classes:               {', '.join(classes)} (Count: {len(classes)})")
    print(f"Features:              {ds.get('features_count', 12)} Selected Network Packet Attributes")
    raw_df = pd.read_csv(dataset_path)
    missing_sum = int(raw_df.isnull().sum().sum())
    print(f"Missing Values:        {missing_sum}")
    dist_strs = [f"{d['class_name']}: {d['count']} ({d['percentage']}%)" for d in ds.get('distribution', [])]
    print(f"Class Distribution:    {'; '.join(dist_strs)}")
    print(f"Class Imbalance:       {'YES' if ds.get('class_imbalance_detected') else 'NO'} ({ds.get('imbalance_ratio', '1:1')})")
    print("=========================================================")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ThreatLens CLI Model Evaluation Utility")
    parser.add_argument("--dataset", type=str, default=None, help="Path to evaluation CSV dataset")
    args = parser.parse_args()
    run_cli_evaluation(dataset_path=args.dataset)
