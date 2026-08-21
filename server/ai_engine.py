"""
ai_engine.py
SecEoKnight — AI model loader and prediction helpers.

Models:
  Phishing  : BiLSTM  (bilstm_domain_model.h5 + tokenizer.pkl)
  Malware   : CNN, ViT, 1D-CNN-LSTM  (.keras files)

Place your trained model files inside:
  server/models/phishing/bilstm_domain_model.h5
  server/models/phishing/tokenizer.pkl
  server/models/malware/CNN.keras
  server/models/malware/ViT.keras
  server/models/malware/1D-CNN-LSTM.keras

If any model file is missing the engine starts in degraded mode
and returns an error response for that model type only.
"""

import os
import io
import base64
import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

# ── State ─────────────────────────────────────────────────────────────────────
_phishing_model    = None
_tokenizer         = None
_malware_models    = {}
_ai_ready          = False

MAX_SEQUENCE_LENGTH = 100
IMG_SIZE            = (224, 224)

MALWARE_CLASSES = [
    "Adialer.C", "Agent.FYI", "Allaple.A", "Allaple.L", "Alueron.gen!J",
    "Autorun.K", "C2LOP.gen!g", "C2LOP.P", "Dialplatform.B", "Dontovo.A",
    "Fakerean", "Instantaccess", "Lolyda.AA1", "Lolyda.AA2", "Lolyda.AA3",
    "Lolyda.AT", "Malex.gen!J", "Obfuscator.AD", "Rbot!gen", "Skintrim.N",
    "Swizzor.gen!E", "Swizzor.gen!I", "VB.AT", "Wintrim.BX", "Yuner.A",
]

LEGITIMATE_DOMAINS = [
    "google.com", "google.co.uk", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "stackoverflow.com", "wikipedia.org", "youtube.com",
    "netflix.com", "spotify.com", "paypal.com", "ebay.com", "yahoo.com",
    "bing.com", "duckduckgo.com", "mozilla.org",
    # Added 2026-08-21 after real production false positives. The phishing
    # model only sees the URL text itself (no reputation/age/traffic data),
    # so any legitimate site it wasn't trained on reads as "unfamiliar" --
    # the same signal a freshly-registered phishing domain gives off. These
    # scored 0.56-0.98 ("phishing") in real traffic despite being well-known,
    # legitimate sites.
    "chatgpt.com", "chat.openai.com", "openai.com",
    "putty.org", "chiark.greenend.org.uk",
    "virustotal.com", "filebin.net",
]


def load_models():
    """Load all AI models at startup. Called once from unified_server.py."""
    global _phishing_model, _tokenizer, _malware_models, _ai_ready

    try:
        import tensorflow as tf
        import pickle
    except ImportError:
        print("[AI] TensorFlow or pickle not installed — AI features disabled.")
        return

    # ── Phishing model ────────────────────────────────────────────────────────
    phishing_dir = os.path.join(MODELS_DIR, "phishing")
    model_path   = os.path.join(phishing_dir, "bilstm_domain_model.h5")
    token_path   = os.path.join(phishing_dir, "tokenizer.pkl")

    if os.path.exists(model_path) and os.path.exists(token_path):
        try:
            _phishing_model = tf.keras.models.load_model(model_path)
            with open(token_path, "rb") as f:
                _tokenizer = pickle.load(f)
            print("[AI] Phishing model loaded ✓")
        except Exception as e:
            print(f"[AI] Failed to load phishing model: {e}")
    else:
        print(f"[AI] Phishing model not found at {phishing_dir} — phishing AI disabled.")

    # ── Malware models ────────────────────────────────────────────────────────
    malware_dir = os.path.join(MODELS_DIR, "malware")
    for name in ["CNN", "ViT", "1D-CNN-LSTM"]:
        path = os.path.join(malware_dir, f"{name}.keras")
        if os.path.exists(path):
            try:
                _malware_models[name] = tf.keras.models.load_model(path)
                print(f"[AI] Malware model {name} loaded ✓")
            except Exception as e:
                print(f"[AI] Failed to load {name}: {e}")
        else:
            print(f"[AI] Malware model {name} not found at {path} — skipped.")

    _ai_ready = bool(_phishing_model or _malware_models)
    print(f"[AI] Engine ready — phishing={'yes' if _phishing_model else 'no'}, "
          f"malware models={list(_malware_models.keys())}")


def get_status() -> dict:
    """Return which models are loaded — used by /health endpoint."""
    return {
        "phishing_model":   "loaded" if _phishing_model else "not_loaded",
        "malware_models":   {k: "loaded" for k in _malware_models} or {},
        "available_malware_models": list(_malware_models.keys()),
        "malware_classes":  MALWARE_CLASSES,
    }


# ── Phishing ──────────────────────────────────────────────────────────────────

def _is_whitelisted(url: str) -> bool:
    import re
    m = re.search(r"https?://(?:www\.)?([^/]+)", url.lower())
    if m:
        domain = m.group(1)
        return any(leg in domain for leg in LEGITIMATE_DOMAINS)
    return False


def predict_phishing(url: str) -> dict:
    """
    Returns:
      { phishing: bool, score: float, confidence: str,
        whitelisted: bool, error: str|None }
    """
    if not url:
        return {"error": "No URL provided"}

    if _is_whitelisted(url):
        return {"phishing": False, "score": 0.0,
                "confidence": "High (Whitelisted)", "whitelisted": True}

    if _phishing_model is None or _tokenizer is None:
        return {"error": "Phishing model not loaded",
                "phishing": None, "score": None}

    try:
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        seq    = _tokenizer.texts_to_sequences([url])
        padded = pad_sequences(seq, maxlen=MAX_SEQUENCE_LENGTH)
        pred   = float(_phishing_model.predict(padded, verbose=0)[0][0])

        # Decision threshold raised from a naive >0.5 to >0.90. A bare
        # majority vote gives no margin -- a borderline 0.56 was previously
        # treated identically (full "High"/blocked) to a genuine 0.9997
        # real-phishing score. threat_level now reflects the actual score
        # instead of always being "High", so the dashboard/extension can
        # stop showing every flag at maximum severity.
        label = pred > 0.90
        if pred >= 0.97:
            threat_level = "High"
        elif pred >= 0.90:
            threat_level = "Medium"
        else:
            threat_level = "Low"
        conf = "High" if abs(pred - 0.5) > 0.3 else "Medium"

        return {
            "phishing":     label,
            "score":        round(pred, 4),
            "confidence":   conf,
            "threat_level": threat_level,
            "whitelisted":  False,
            "error":        None,
        }
    except Exception as e:
        return {"error": str(e), "phishing": None, "score": None}


# ── Malware ───────────────────────────────────────────────────────────────────

def _preprocess_image(image_data) -> "np.ndarray | None":
    try:
        from PIL import Image as PILImage
        if isinstance(image_data, str):
            if "," in image_data:
                image_data = image_data.split(",")[1]
            raw = base64.b64decode(image_data)
        else:
            raw = image_data
        img = PILImage.open(io.BytesIO(raw)).convert("RGB").resize(IMG_SIZE)
        arr = np.array(img, dtype=np.float32) / 255.0
        return np.expand_dims(arr, axis=0)
    except Exception as e:
        print(f"[AI] Image preprocessing failed: {e}")
        return None


def predict_malware(image_data: str, model_name: str = "CNN") -> dict:
    """
    Returns:
      { is_malware: bool, threat_level: str, model_used: str,
        predictions: [...], top_prediction: {...}, error: str|None }
    """
    if not image_data:
        return {"error": "No image data provided"}

    if model_name not in _malware_models:
        available = list(_malware_models.keys())
        if not available:
            return {"error": "No malware models loaded"}
        model_name = available[0]   # fall back to first available

    processed = _preprocess_image(image_data)
    if processed is None:
        return {"error": "Failed to preprocess image"}

    try:
        preds      = _malware_models[model_name].predict(processed, verbose=0)[0]
        top_idx    = np.argsort(preds)[-3:][::-1]
        results    = [
            {
                "malware_type": MALWARE_CLASSES[i],
                "confidence":   round(float(preds[i]), 4),
                "percentage":   f"{preds[i]*100:.2f}%",
            }
            for i in top_idx
        ]

        top_conf   = float(preds[top_idx[0]])
        sec_conf   = float(preds[top_idx[1]]) if len(top_idx) > 1 else 0.0
        conf_diff  = top_conf - sec_conf
        entropy    = float(-np.sum(preds * np.log(preds + 1e-10)))
        max_ent    = float(np.log(len(preds)))
        norm_ent   = entropy / max_ent if max_ent else 0

        # Conservative: only flag as malware if very confident
        is_malware    = top_conf > 0.95 and conf_diff > 0.6
        threat_level  = "High" if is_malware else "Safe"

        return {
            "is_malware":    is_malware,
            "threat_level":  threat_level,
            "model_used":    model_name,
            "predictions":   results,
            "top_prediction": results[0] if results else None,
            "diagnostics": {
                "top_confidence":     round(top_conf, 4),
                "confidence_diff":    round(conf_diff, 4),
                "normalized_entropy": round(norm_ent, 4),
            },
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}
