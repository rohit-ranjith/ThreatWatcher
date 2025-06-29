import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from joblib import dump

#load packet log for training
df = pd.read_csv("packet_log.csv")

#replace placeholders and stuff
df.replace("-", "unknown", inplace=True)
df.fillna("unknown", inplace=True)

#numeric conversion
for col in ["src_port", "dst_port", "length"]:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(-1)

#defining fields
categorical = ["src_ip", "dst_ip", "protocol_name", "tcp_flags"]
numeric = ["src_port", "dst_port", "length"]

#column transformer
preprocessor = ColumnTransformer([
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
    ("num", StandardScaler(), numeric)
])

#create pipeline with preprocessing + Isolation Forest
pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("clf", IsolationForest(contamination=0.01, random_state=42))
])

#train and save 
pipeline.fit(df)
dump(pipeline, "anomaly_model.joblib")
print("Model trained and saved as joblib")
