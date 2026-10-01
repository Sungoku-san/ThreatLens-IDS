import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve, auc
from backend.config import BASE_DIR, Config

class ModelComparisonPlotter:
    @staticmethod
    def generate_comparison_plots(results_df, confusion_matrices, feature_importances, y_test, X_test, models_dict):
        """
        Generates and saves model performance comparison visual charts to the static web directory.
        """
        img_dir = os.path.join(BASE_DIR, 'static', 'img')
        os.makedirs(img_dir, exist_ok=True)
        
        # 1. Performance Metrics Bar Chart Comparison
        plt.figure(figsize=(10, 6))
        metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        models = results_df['model_name'].tolist()
        x = np.arange(len(models))
        width = 0.18
        
        colors = ['#3B82F6', '#10B981', '#F59E0B', '#8B5CF6']
        for i, metric in enumerate(metrics):
            values = results_df[metric].tolist()
            plt.bar(x + (i - 1.5) * width, values, width, label=metric.capitalize(), color=colors[i % len(colors)], alpha=0.9)
            
        plt.title('Classifier Performance Metrics Comparison', fontsize=14, fontweight='bold', pad=15)
        plt.ylim(0, 1.1)
        plt.ylabel('Score')
        plt.xlabel('Machine Learning Model')
        plt.xticks(x, models, rotation=15)
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.grid(axis='y', linestyle='--', alpha=0.3)
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
                        y_test_bin = (y_test > 0).astype(int)
                        probs_malicious = np.sum(probs[:, 1:], axis=1)
                        fpr, tpr, _ = roc_curve(y_test_bin, probs_malicious)
                    else:
                        fpr, tpr, _ = roc_curve(y_test, probs[:, 1])
                    roc_auc = auc(fpr, tpr)
                    plt.plot(fpr, tpr, lw=2, label=f'{model_name} (AUC = {roc_auc:.4f})')
                except Exception:
                    pass
                    
        plt.plot([0, 1], [0, 1], 'k--', lw=1.5, label='Baseline Guess (AUC = 0.5000)')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curves', fontsize=14, fontweight='bold')
        plt.legend(loc='lower right')
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(img_dir, 'roc_curve.png'), dpi=150)
        plt.close()

        # 3. Confusion Matrix (Best Model)
        best_row = results_df.sort_values(by='f1_score', ascending=False).iloc[0]
        best_model_name = best_row['model_name']
        best_cm = np.array(confusion_matrices.get(best_model_name, [[0, 0], [0, 0]]))
        
        plt.figure(figsize=(6, 5))
        plt.imshow(best_cm, interpolation='nearest', cmap=plt.cm.Blues)
        plt.title(f'Confusion Matrix Heatmap\n({best_model_name})', fontsize=12, fontweight='bold', pad=10)
        plt.colorbar()
        tick_marks = np.arange(len(best_cm))
        plt.xticks(tick_marks, [f'Class {i}' for i in tick_marks], rotation=45)
        plt.yticks(tick_marks, [f'Class {i}' for i in tick_marks])
        
        thresh = best_cm.max() / 2.0 if best_cm.max() > 0 else 1.0
        for i in range(best_cm.shape[0]):
            for j in range(best_cm.shape[1]):
                plt.text(j, i, format(best_cm[i, j], 'd'),
                         ha="center", va="center",
                         color="white" if best_cm[i, j] > thresh else "black",
                         fontweight="bold")
                         
        plt.ylabel('Actual Threat Label')
        plt.xlabel('Predicted Threat Label')
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
            }).sort_values(by='Importance', ascending=True).tail(10)
            
            plt.barh(importance_df['Feature'], importance_df['Importance'], color='#06B6D4', alpha=0.85)
            plt.title(f'Top 10 Feature Importances\n({best_model_name})', fontsize=12, fontweight='bold', pad=10)
            plt.xlabel('Gini Importance / Gain Weight')
            plt.ylabel('Packet Feature Name')
            plt.grid(axis='x', linestyle='--', alpha=0.3)
            plt.tight_layout()
            plt.savefig(os.path.join(img_dir, 'feature_importance.png'), dpi=150)
        plt.close()
