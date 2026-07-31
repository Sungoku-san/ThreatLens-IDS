import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve, auc
from backend.config import Config

class ModelComparisonPlotter:
    @staticmethod
    def generate_comparison_plots(results_df, confusion_matrices, feature_importances, y_test, X_test, models_dict):
        """
        Generates and saves model performance comparison visual charts to the static web directory.
        """
        img_dir = os.path.join(Config.BASE_DIR, 'static', 'img')
        os.makedirs(img_dir, exist_ok=True)
        
        # Set styling context
        sns.set_theme(style="darkgrid")
        
        # 1. Performance Metrics Bar Chart Comparison
        plt.figure(figsize=(10, 6))
        metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        df_melted = pd.melt(results_df, id_vars=['model_name'], value_vars=metrics, 
                            var_name='Metric', value_name='Value')
        
        sns.barplot(x='model_name', y='Value', hue='Metric', data=df_melted, palette='viridis')
        plt.title('Classifier Performance Metrics Comparison', fontsize=14, fontweight='bold', pad=15)
        plt.ylim(0, 1.1)
        plt.ylabel('Score')
        plt.xlabel('Machine Learning Model')
        plt.xticks(rotation=15)
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.savefig(os.path.join(img_dir, 'model_comparison.png'), dpi=150)
        plt.close()

        # 2. ROC Curves for available models
        plt.figure(figsize=(8, 6))
        for model_name, model in models_dict.items():
            if hasattr(model, "predict_proba"):
                try:
                    probs = model.predict_proba(X_test)
                    if probs.shape[1] > 2:
                        # For multi-class (OVR), let's plot average micro ROC or target class 1 (Malicious)
                        # We will aggregate all binary outputs for target class 1
                        y_test_bin = (y_test > 0).astype(int)
                        probs_malicious = np.sum(probs[:, 1:], axis=1) # combine malicious probabilities
                        fpr, tpr, _ = roc_curve(y_test_bin, probs_malicious)
                    else:
                        fpr, tpr, _ = roc_curve(y_test, probs[:, 1])
                    roc_auc = auc(fpr, tpr)
                    plt.plot(fpr, tpr, label=f'{model_name} (AUC = {roc_auc:.4f})')
                except Exception:
                    pass
                    
        plt.plot([0, 1], [0, 1], 'k--', label='Baseline Guess (AUC = 0.5000)')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curves', fontsize=14, fontweight='bold')
        plt.legend(loc='lower right')
        plt.tight_layout()
        plt.savefig(os.path.join(img_dir, 'roc_curve.png'), dpi=150)
        plt.close()

        # 3. Confusion Matrix (Best Model)
        best_row = results_df.sort_values(by='f1_score', ascending=False).iloc[0]
        best_model_name = best_row['model_name']
        best_cm = np.array(confusion_matrices.get(best_model_name, [[0, 0], [0, 0]]))
        
        plt.figure(figsize=(6, 5))
        sns.heatmap(best_cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                    annot_kws={"size": 12, "weight": "bold"})
        plt.title(f'Confusion Matrix Heatmap\n({best_model_name})', fontsize=12, fontweight='bold', pad=10)
        plt.xlabel('Predicted Threat Label')
        plt.ylabel('Actual Threat Label')
        plt.tight_layout()
        plt.savefig(os.path.join(img_dir, 'confusion_matrix.png'), dpi=150)
        plt.close()

        # 4. Feature Importance Plot (Best Model)
        plt.figure(figsize=(10, 6))
        features_dict = feature_importances.get(best_model_name, {})
        if features_dict:
            importance_df = pd.DataFrame({
                'Feature': list(features_dict.keys()),
                'Importance': list(features_dict.values())
            }).sort_values(by='Importance', ascending=False)
            
            sns.barplot(x='Importance', y='Feature', data=importance_df.head(10), palette='mako')
            plt.title(f'Top 10 Feature Importances\n({best_model_name})', fontsize=12, fontweight='bold', pad=10)
            plt.xlabel('Gini Importance / Gain Weight')
            plt.ylabel('Packet Feature name')
            plt.tight_layout()
            plt.savefig(os.path.join(img_dir, 'feature_importance.png'), dpi=150)
        plt.close()
