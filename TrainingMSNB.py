import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import pickle
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
class MSNBNCH:
    def __init__(self):
        self.class_priors = {}
        self.conditional_prob = {}
        self.classes = None

    def fit(self, X, y):
        self.classes = np.unique(y)
        n_samples, n_features = X.shape
        for c in self.classes:
            X_c = X[y == c]
            self.class_priors[c] = len(X_c) / n_samples
            self.conditional_prob[c] = {
                "mean": X_c.mean(axis=0),
                "var": X_c.var(axis=0) + 1e-6
            }

    def calculate_likelihood(self, class_mean, class_var, x):
        exponent = np.exp(-((x - class_mean) ** 2) / (2 * class_var))
        return (1 / (np.sqrt(2 * np.pi * class_var))) * exponent

    def predict(self, X, epsilon=1e-9):
        predictions = []
        for x in X.to_numpy():
            class_prob = {}
            for c in self.classes:
                class_prob[c] = np.log(self.class_priors[c] + epsilon)
                mean = self.conditional_prob[c]["mean"]
                var = self.conditional_prob[c]["var"]
                likelihood = self.calculate_likelihood(mean, var, x)
                class_prob[c] += np.sum(np.log(likelihood + epsilon))
            predictions.append(max(class_prob, key=class_prob.get))
        return np.array(predictions)

    def evaluate(self, X, y):
        predictions = self.predict(X)
        accuracy = np.mean(predictions == y)
        return accuracy


def train_model(data_path):
    # Load và xử lý dữ liệu
    data = pd.read_csv(data_path, encoding='latin1')
    data['type'] = data['type'].apply(lambda x: 1 if "benign" in x else 0)

    X = data.drop(columns=['url', 'type']).apply(pd.to_numeric, errors='coerce').fillna(0)
    y = data['type']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Huấn luyện mô hình
    nb = MSNBNCH()
    nb.fit(X_train, y_train)
    y_pred = nb.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    # Hiển thị kết quả
    print(f'Accuracy: {accuracy:.2f}')
    print(f'Precision: {precision:.2f}')
    print(f'Recall: {recall:.2f}')
    print(f'F1 Score: {f1:.2f}')

    return nb, X_test
    #accuracy = nb.evaluate(X_test, y_test)
    #print(f'Accuracy: {accuracy}')
    #return nb, X_test



def save_model(model, file_path):
    with open(file_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved to {file_path}")

def load_model(file_path):
    with open(file_path, 'rb') as f:
        model = pickle.load(f)
    print(f"Model loaded from {file_path}")
    return model


if __name__ == "__main__": 
    model, _ = train_model('D:/Downloads/Dataset1/checkdataseturl2.csv') 
    save_model(model, 'D:/Downloads/Dataset1/model.pkl')