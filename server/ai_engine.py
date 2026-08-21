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
import time
import base64
import numpy as np
import requests

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

# ── Google Safe Browsing (optional, real threat-intel backstop) ────────────────
# The local BiLSTM model only ever sees the URL's text -- no reputation, age,
# or traffic data -- so it keeps flagging legitimate-but-unfamiliar sites as
# phishing (chatgpt.com, putty.org, virustotal.com, dropbox.com, slack.com,
# medium.com, discord.com, accounts.zoho.in all hit this in real production
# traffic on 2026-08-21, some at 100% "confidence"). No threshold survives
# that: a real phishing test sample scored 0.9997 while a false positive
# (medium.com) scored 0.9917 -- a gap too thin to tune around.
#
# Safe Browsing is the same database Chrome itself uses, continuously updated
# from real-world data, free for non-commercial use. Configuring
# SECEOKNIGHT_SAFE_BROWSING_KEY makes it the primary signal: if Safe Browsing
# has NOT flagged a URL, it's treated as safe regardless of what the fragile
# local model says, which is what actually stops known-legitimate sites from
# being misreported. The local model still runs as a secondary, much lower
# confidence signal for brand-new phishing domains Safe Browsing hasn't
# indexed yet. Leave the key unset and behavior is unchanged (local model +
# whitelist only).
SAFE_BROWSING_API_KEY = os.environ.get("SECEOKNIGHT_SAFE_BROWSING_KEY", "").strip()
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

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
    "zoho.com", "zoho.in", "accounts.zoho.in", "accounts.zoho.com",
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


def _check_safe_browsing(url: str) -> "bool | None":
    """
    Queries Google Safe Browsing's threatMatches:find endpoint.
    Returns:
      True  -- Safe Browsing has this URL flagged as a known threat
      False -- Safe Browsing does NOT have this URL flagged (checked, clean)
      None  -- couldn't determine (no key configured, network error, timeout)
    Fails closed on error in the sense that matters here: on any failure we
    return None and the caller falls back to local-model-only behavior,
    exactly like before this integration existed -- never blocks a request
    or crashes the caller just because Google's API had a bad moment.
    """
    if not SAFE_BROWSING_API_KEY:
        return None
    try:
        body = {
            "client": {"clientId": "seceoknight", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            json=body,
            timeout=3,
        )
        if resp.status_code != 200:
            return None
        matches = resp.json().get("matches", [])
        return len(matches) > 0
    except Exception:
        return None


def predict_phishing(url: str) -> dict:
    """
    Returns:
      { phishing: bool, score: float, confidence: str,
        whitelisted: bool, source: str, error: str|None }
    """
    if not url:
        return {"error": "No URL provided"}

    if _is_whitelisted(url):
        return {"phishing": False, "score": 0.0,
                "confidence": "High (Whitelisted)", "whitelisted": True,
                "source": "whitelist"}

    # Safe Browsing first, if configured -- it's the same continuously
    # updated database Chrome itself checks against, so it's a far more
    # reliable signal than the local model for anything it has an opinion
    # on. A confirmed match is trusted outright; the local model isn't even
    # consulted in that case.
    sb_result = _check_safe_browsing(url)
    if sb_result is True:
        return {
            "phishing": True, "score": 1.0,
            "confidence": "Confirmed (Google Safe Browsing)",
            "threat_level": "High", "whitelisted": False,
            "source": "safe_browsing", "error": None,
        }

    if _phishing_model is None or _tokenizer is None:
        return {"error": "Phishing model not loaded",
                "phishing": None, "score": None}

    try:
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        seq    = _tokenizer.texts_to_sequences([url])
        padded = pad_sequences(seq, maxlen=MAX_SEQUENCE_LENGTH)
        pred   = float(_phishing_model.predict(padded, verbose=0)[0][0])

        # Decision threshold raised again, from >0.90 to >=0.995. A live
        # test on 10 ordinary, well-known sites (reddit, dropbox, notion,
        # slack, zoom, nytimes, medium, discord, cloudflare, salesforce --
        # none on the whitelist) showed 4/10 still scored "phishing" at the
        # 0.90 bar (dropbox 0.9704, slack 0.976, medium 0.9917, discord
        # 0.976). The one confirmed real-phishing sample we have scored
        # 0.9997 -- only 0.008 above medium.com's false positive. That gap
        # is too thin for this model's raw score to reliably separate
        # "legitimate site" from "actual phishing" below near-certainty.
        label = pred >= 0.995
        threat_level = "High" if pred >= 0.995 else "Low"
        conf = "High" if abs(pred - 0.5) > 0.3 else "Medium"
        source = "local_model"

        # sb_result is False here means Safe Browsing was checked and came
        # back CLEAN -- not "unknown", genuinely checked and not flagged.
        # That's strong evidence against the local model's own high score,
        # since every false positive seen in production so far (chatgpt,
        # putty, virustotal, dropbox, slack, medium, discord, zoho) is a
        # site Safe Browsing would never flag. Demote instead of trusting
        # the fragile local score alone: still visible for review, but no
        # longer shown as a confident "blocked" phishing alert.
        if sb_result is False and label:
            label = False
            threat_level = "Low"
            conf = f"Unconfirmed (local model {round(pred,4)}, not found in Safe Browsing)"
            source = "local_model_unconfirmed"

        return {
            "phishing":     label,
            "score":        round(pred, 4),
            "confidence":   conf,
            "threat_level": threat_level,
            "whitelisted":  False,
            "source":       source,
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
