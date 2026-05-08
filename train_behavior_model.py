import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DATASET_FILE = "behavior_dataset.csv"
MODEL_FILE = "behavior_model.pkl"
ENCODER_FILE = "behavior_encoders.pkl"

print("=" * 70)
print("TRAINING BEHAVIOR AI MODEL")
print("=" * 70)

df = pd.read_csv(DATASET_FILE)

print("\nDataset loaded:")
print(f"Rows: {len(df)}")
print("\nLabel distribution:")
print(df["behavior_label"].value_counts())

features = ["role", "action", "category", "sensitivity"]
target = "behavior_label"

X_raw = df[features]
y_raw = df[target]

# Encode categorical input features
try:
    encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
except TypeError:
    encoder = OneHotEncoder(sparse=False, handle_unknown="ignore")

X = encoder.fit_transform(X_raw)

# Encode labels: normal / unusual / abnormal
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y_raw)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=18,
    random_state=42,
    class_weight="balanced"
)

print("\nTraining model...")
model.fit(X_train, y_train)

print("\nEvaluating model...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy:.2%}")

print("\nClassification report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=label_encoder.classes_
))

print("\nConfusion matrix:")
print(confusion_matrix(y_test, y_pred))

joblib.dump(model, MODEL_FILE)

joblib.dump({
    "onehot_encoder": encoder,
    "label_encoder": label_encoder,
    "features": features
}, ENCODER_FILE)

print("\nSaved files:")
print(f"- {MODEL_FILE}")
print(f"- {ENCODER_FILE}")

print("\nTest predictions:")

test_cases = [
    ["Engineer", "read", "Engineering", "MEDIUM"],
    ["Engineer", "write/edit", "Engineering", "HIGH"],
    ["Engineer", "delete", "Engineering", "HIGH"],
    ["Engineer", "upload/share", "Finance", "HIGH"],
    ["Lawyer", "write/edit", "Legal", "HIGH"],
    ["Normal Employee", "read", "Finance", "HIGH"],
    ["IT Admin", "read", "Credentials/Secrets", "CRITICAL"],
    ["Sales", "upload/share", "Customer Data", "HIGH"]
]

test_df = pd.DataFrame(test_cases, columns=features)
test_X = encoder.transform(test_df)

predictions = model.predict(test_X)
probabilities = model.predict_proba(test_X)

for case, pred, probs in zip(test_cases, predictions, probabilities):
    label = label_encoder.inverse_transform([pred])[0]
    confidence = max(probs)
    print(f"{case} -> {label} | confidence={confidence:.2f}")

print("\nBehavior AI training complete.")