"""
train_phishing_model.py — SecEoKnight Phishing Model Trainer
=============================================================
Run this once on the Ubuntu security server to generate the BiLSTM
phishing detection model used by the unified server.

Requirements: TensorFlow, scikit-learn, pandas, numpy
(already covered by server requirements.txt)

Usage:
    cd /opt/seceoknight
    source venv/bin/activate
    python3 scripts/train_phishing_model.py

Output files (auto-placed in server/models/phishing/):
    bilstm_domain_model.h5   ← Keras model
    tokenizer.pkl            ← Fitted tokenizer
"""

import os
import sys
import pickle
import pathlib
import numpy as np
import pandas as pd

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = pathlib.Path(__file__).parent.resolve()
DATA_PATH   = SCRIPT_DIR / "data" / "phishing.csv"
OUTPUT_DIR  = SCRIPT_DIR.parent / "server" / "models" / "phishing"

# ── Hyper-parameters (match what unified_server/ai_engine expect) ──────────────
MAX_WORDS       = 10000
MAX_SEQ_LEN     = 100
EMBEDDING_DIM   = 128
EPOCHS          = 5
BATCH_SIZE      = 64
TEST_SPLIT      = 0.2
RANDOM_STATE    = 42
# ──────────────────────────────────────────────────────────────────────────────


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── 1. Load data ──────────────────────────────────────────────────────────
    print(f"[1/6] Loading dataset: {DATA_PATH}")
    if not DATA_PATH.exists():
        print(f"ERROR: phishing.csv not found at {DATA_PATH}")
        sys.exit(1)

    df = pd.read_csv(DATA_PATH, encoding="latin-1", engine="python", on_bad_lines="skip")
    print(f"      {len(df):,} rows loaded.  Columns: {list(df.columns)}")

    if "domain" not in df.columns or "label" not in df.columns:
        print("ERROR: CSV must contain 'domain' and 'label' columns.")
        sys.exit(1)

    # ── 2. Preprocess ─────────────────────────────────────────────────────────
    print("[2/6] Preprocessing …")

    # Coerce numeric columns that may arrive as strings
    for col in ["ranking", "mld_res", "mld.ps_res", "jaccard_ARrem"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Fill numeric NaNs with median (pandas 3.x Copy-on-Write safe)
    for col in df.select_dtypes(include=np.number).columns:
        if df[col].isnull().any():
            df[col] = df[col].fillna(df[col].median())

    X_domain = df["domain"].astype(str)
    y_labels = df["label"].astype("category").cat.codes

    label_dist = y_labels.value_counts()
    print(f"      Label distribution — {dict(label_dist)}")

    # ── 3. Tokenise & pad ─────────────────────────────────────────────────────
    print("[3/6] Tokenising domain names …")
    from tensorflow.keras.preprocessing.text import Tokenizer        # noqa: E402
    from tensorflow.keras.preprocessing.sequence import pad_sequences # noqa: E402

    tokenizer = Tokenizer(num_words=MAX_WORDS)
    tokenizer.fit_on_texts(X_domain)
    sequences  = tokenizer.texts_to_sequences(X_domain)
    X_padded   = pad_sequences(sequences, maxlen=MAX_SEQ_LEN)
    print(f"      Vocabulary size: {len(tokenizer.word_index):,}  |  Padded shape: {X_padded.shape}")

    # ── 4. Train / test split ─────────────────────────────────────────────────
    from sklearn.model_selection import train_test_split              # noqa: E402
    X_train, X_test, y_train, y_test = train_test_split(
        X_padded, y_labels.values,
        test_size=TEST_SPLIT, random_state=RANDOM_STATE
    )
    print(f"[4/6] Split — train: {len(X_train):,}  test: {len(X_test):,}")

    # ── 5. Build & train BiLSTM ───────────────────────────────────────────────
    print("[5/6] Building BiLSTM model …")
    from tensorflow.keras.models import Sequential                    # noqa: E402
    from tensorflow.keras.layers import (                             # noqa: E402
        Embedding, Bidirectional, LSTM, Dropout, Dense
    )
    from tensorflow.keras.callbacks import EarlyStopping             # noqa: E402

    model = Sequential([
        Embedding(input_dim=MAX_WORDS, output_dim=EMBEDDING_DIM, input_length=MAX_SEQ_LEN),
        Bidirectional(LSTM(64, return_sequences=True)),
        Dropout(0.2),
        Bidirectional(LSTM(32)),
        Dropout(0.2),
        Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()

    es = EarlyStopping(monitor="val_loss", patience=2, restore_best_weights=True)
    history = model.fit(
        X_train, y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.2,
        callbacks=[es],
        verbose=1,
    )

    train_acc = history.history["accuracy"][-1]
    val_acc   = history.history["val_accuracy"][-1]
    print(f"      Final train accuracy : {train_acc:.4f}")
    print(f"      Final val   accuracy : {val_acc:.4f}")

    # Evaluate on held-out test set
    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f"      Test accuracy: {acc:.4f}  |  Test loss: {loss:.4f}")

    # ── 6. Save outputs ───────────────────────────────────────────────────────
    print("[6/6] Saving model and tokenizer …")

    model_path     = OUTPUT_DIR / "bilstm_domain_model.h5"
    tokenizer_path = OUTPUT_DIR / "tokenizer.pkl"

    model.save(str(model_path))
    with open(tokenizer_path, "wb") as f:
        pickle.dump(tokenizer, f)

    print(f"\n  Model saved   : {model_path}  ({model_path.stat().st_size / 1e6:.1f} MB)")
    print(f"  Tokenizer saved: {tokenizer_path}  ({tokenizer_path.stat().st_size / 1e3:.1f} KB)")
    print("\n✅  Training complete. Restart seceoknight service to load the new model:")
    print("    sudo systemctl restart seceoknight")


if __name__ == "__main__":
    main()
