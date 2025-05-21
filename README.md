# PhishPatrol

PhishPatrol is an advanced phishing detection system powered by a large language model (LLM) and ONNX for fast inference. It provides both a REST API (FastAPI) for batch URL analysis and a Chrome browser extension for real-time webpage scanning.

## Features

- **LLM-powered URL Analysis:** Uses a fine-tuned transformer model (DeBERTa) exported to ONNX for fast, accurate phishing detection.
- **Rule-based & ML Hybrid:** Combines machine learning with rule-based heuristics for robust detection and explainable results.
- **Batch Scanning:** Analyze multiple URLs in a single API call.
- **Browser Extension:** Chrome extension scans all links on the current page and provides a detailed security verdict.
- **Detailed Explanations:** Each result includes reasons for the verdict, improving transparency and user trust.

---

## Project Structure

```
PhishPatrol/
│
└── backend/
    ├── app.py                # FastAPI backend for phishing detection
    ├── requirements.txt       # Python dependencies
    └── phishing_detector.onnx # ONNX model for fast inference
│
├── popup/                # Chrome extension source
│   ├── popup.html
│   ├── popup.js
│   ├── popup.css
│   ├── manifest.json
│   └── logo.png
│
├── PhishPatrol.ipynb      # Jupyter notebook for model training and experiments
└── README.md              # This file
```

---

## Backend API

### Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the API:**
   ```bash
   python app.py
   ```
   The API will be available at `http://localhost:8000`.

### API Usage

- **Endpoint:** `POST /scan`
- **Request Body:**
  ```json
  {
    "urls": ["https://example.com", "http://suspicious-site.xyz"]
  }
  ```
- **Response:**
  ```json
  {
    "time_taken": "0.23s",
    "total_urls": 2,
    "legitimate": 1,
    "phishing": 1,
    "overall_verdict": "safe",
    "average_confidence": 0.87,
    "results": [
      {
        "url": "https://example.com",
        "verdict": "legitimate",
        "confidence": 0.12,
        "reasons": ["No suspicious patterns detected"]
      },
      ...
    ]
  }
  ```

---

## Chrome Extension

### Features

- Scans all links on the current page.
- Shows verdict, confidence, and detailed reasons.
- Modern, user-friendly UI.

### Installation

1. Go to `chrome://extensions/` in your browser.
2. Enable "Developer mode".
3. Click "Load unpacked" and select the `popup/` directory.

### Usage

- Click the PhishPatrol icon in your browser.
- Click "INITIATE DEEP SCAN" to analyze all links on the current page.
- View the verdict, confidence, and detailed report in the popup.

---

## Model Training

- See `PhishPatrol.ipynb` for data preprocessing, feature engineering, and model training.
- The ONNX model (`phishing_detector.onnx`) is used for fast inference in the backend.

---

## Dependencies

- onnxruntime
- numpy
- transformers
- fastapi
- pydantic
- uvicorn[standard]
- tldextract
- tiktoken
- sentencepiece
- torch

Install all with:
```bash
pip install -r requirements.txt
```

---

## License

Apache-2.0

---

## Acknowledgements

- [HuggingFace Transformers](https://huggingface.co/transformers/)
- [ONNX Runtime](https://onnxruntime.ai/)
- [FastAPI](https://fastapi.tiangolo.com/)

---

**For more details, see the code and comments in each file.**
