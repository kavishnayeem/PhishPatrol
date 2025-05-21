import onnxruntime as ort
import numpy as np
from transformers import AutoTokenizer
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from concurrent.futures import ThreadPoolExecutor
import tldextract
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import time
import re
from urllib.parse import urlparse
import string
from collections import Counter

class ONNXPhishingDetector:
    def __init__(self, model_path="phishing_detector.onnx"):
        # Initialize with optimized settings and cache
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/deberta-v3-base", local_files_only=False)
        self.session = ort.InferenceSession(
            model_path,
            providers=['CPUExecutionProvider'],  # Removed CoreMLExecutionProvider due to errors
            sess_options=self._get_optimized_options()
        )
        self.model_expected_length = 128
        self.extract = tldextract.TLDExtract(include_psl_private_domains=True)
        self.url_cache = {}  # Cache for URL analysis results
        self.thread_pool = ThreadPoolExecutor(max_workers=32)  # Increased thread pool size for better parallelism
        
        # Comprehensive lists for pattern matching
        self.suspicious_keywords = {
            'login': 'credential-related',
            'signin': 'credential-related',
            'account': 'credential-related', 
            'password': 'credential-related',
            'verify': 'verification-related',
            'secure': 'security-related',
            'banking': 'financial-related',
            'paypal': 'financial-related',
            'wallet': 'financial-related',
            'bitcoin': 'cryptocurrency-related',
            'crypto': 'cryptocurrency-related',
            'authenticate': 'authentication-related',
            'authorize': 'authentication-related',
            'validation': 'verification-related',
            'confirm': 'verification-related'
        }
        
        self.legitimate_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.mil', '.int'}
        self.suspicious_tlds = {'.xyz', '.top', '.buzz', '.country', '.stream', '.gq', '.tk', '.ml'}
        
        # Brand protection patterns
        self.common_brands = {
            'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal', 
            'netflix', 'linkedin', 'twitter', 'instagram'
        }

    def _get_optimized_options(self):
        # Optimize ONNX session options
        options = ort.SessionOptions()
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        # Note: Changing these thread values doesn't significantly impact performance
        options.intra_op_num_threads = 4
        options.inter_op_num_threads = 4
        options.enable_mem_pattern = True
        options.enable_cpu_mem_arena = True
        return options

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of domain to detect random-looking strings"""
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * np.log2(p) for p in prob)
        return entropy

    def _check_character_distribution(self, domain):
        """Analyze character distribution patterns"""
        if not domain:  # Handle empty domain case
            return 0.0, 0.0
            
        char_counts = Counter(domain)
        total_chars = len(domain)
        
        # Check for unusual character distributions
        digit_ratio = sum(c.isdigit() for c in domain) / total_chars
        consonant_ratio = sum(c in 'bcdfghjklmnpqrstvwxyz' for c in domain.lower()) / total_chars
        
        return digit_ratio, consonant_ratio

    def _analyze_url_structure(self, url, ext):
        reasons = []
        parsed = urlparse(url)
        domain = ext.domain
        
        # 1. Domain Analysis
        domain_length = len(domain)
        entropy = self._calculate_entropy(domain)
        digit_ratio, consonant_ratio = self._check_character_distribution(domain)
        
        # Check domain composition
        if domain_length > 20:
            reasons.append(f"Suspicious: Domain length ({domain_length} chars) exceeds normal range")
        
        if entropy > 4.5:
            reasons.append(f"Suspicious: High domain entropy ({entropy:.2f}) suggests randomly generated name")
            
        if digit_ratio > 0.4:
            reasons.append(f"Suspicious: Unusual number of digits ({digit_ratio:.1%} of domain)")
            
        if consonant_ratio > 0.7:
            reasons.append(f"Suspicious: Unusual consonant pattern ({consonant_ratio:.1%} of domain)")

        # 2. Brand Impersonation Detection
        for brand in self.common_brands:
            if brand in domain and brand != domain:
                if re.search(f"{brand}[^a-zA-Z]", domain) or re.search(f"[^a-zA-Z]{brand}", domain):
                    reasons.append(f"High Risk: Potential brand impersonation of {brand}")

        # 3. URL Component Analysis
        if parsed.username or parsed.password:
            reasons.append("High Risk: URL contains embedded credentials")
            
        if parsed.port and parsed.port not in (80, 443):
            reasons.append(f"Suspicious: Non-standard port number ({parsed.port})")

        # 4. Path Analysis
        if parsed.path:
            path_segments = parsed.path.split('/')
            if len(path_segments) > 4:
                reasons.append(f"Suspicious: Deep URL structure ({len(path_segments)} levels)")
            
            # Check for suspicious file extensions
            if any(segment.endswith(('.exe', '.dll', '.bat', '.sh')) for segment in path_segments):
                reasons.append("High Risk: Contains executable file extension")

        # 5. Query Parameter Analysis
        if parsed.query:
            query_params = parsed.query.split('&')
            suspicious_params = [p for p in query_params if any(k in p.lower() for k in ['pass', 'pwd', 'token', 'key'])]
            if suspicious_params:
                reasons.append("Suspicious: Query contains sensitive parameter names")

        # 6. Special Pattern Detection
        if len(re.findall(r'[.-]', domain)) > 4:
            reasons.append("Suspicious: Excessive use of dots/hyphens in domain")
            
        if re.search(r'([a-zA-Z0-9])\1{3,}', domain):
            reasons.append("Suspicious: Repeated character pattern detected")

        # 7. TLD Analysis
        if ext.suffix in self.suspicious_tlds:
            reasons.append(f"Suspicious: Known high-risk TLD (.{ext.suffix})")
        elif ext.suffix not in [tld.strip('.') for tld in self.legitimate_tlds]:
            reasons.append(f"Suspicious: Uncommon TLD (.{ext.suffix})")

        # 8. Keyword Analysis
        found_keywords = []
        for keyword, category in self.suspicious_keywords.items():
            if keyword in f"{domain}{parsed.path}".lower():
                found_keywords.append(f"{keyword} ({category})")
        
        if found_keywords:
            reasons.append(f"Suspicious: Contains sensitive keywords: {', '.join(found_keywords)}")

        return reasons

    def _batch_preprocess(self, urls):
        processed = []
        for url in urls:
            url = url.strip().lower()
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            processed.append(url)
        return processed

    def _batch_tokenize(self, urls):
        return self.tokenizer(
            urls,
            max_length=self.model_expected_length,
            truncation=True,
            padding="max_length",
            return_tensors="np"
        )

    def _predict_thread(self, urls):
        """Process a batch of URLs in a separate thread"""
        processed_urls = self._batch_preprocess(urls)
        inputs = self._batch_tokenize(processed_urls)
        
        ort_inputs = {
            "input_ids": inputs["input_ids"].astype(np.int64),
            "attention_mask": inputs["attention_mask"].astype(np.int64)
        }
        
        try:
            logits = self.session.run(None, ort_inputs)[0]
            probabilities = np.exp(logits) / np.sum(np.exp(logits), axis=-1, keepdims=True)
            
            results = []
            for url, prob in zip(urls, probabilities[:, 1]):
                ext = self.extract(url)
                reasons = self._analyze_url_structure(url, ext)
                
                if prob > 0.99:
                    reasons.append(f"Critical: ML model detected strong phishing patterns (confidence: {prob:.2%})")
                    verdict = "phishing"
                else:
                    if not reasons:
                        reasons = ["No suspicious patterns detected"]
                    verdict = "legitimate"
                
                result = {
                    "url": url,
                    "verdict": verdict,
                    "confidence": float(prob),
                    "reasons": set(reasons)
                }
                
                self.url_cache[url] = result
                results.append(result)
                
            return results
        except Exception as e:
            # Fallback to rule-based analysis if model inference fails
            results = []
            for url in urls:
                ext = self.extract(url)
                reasons = self._analyze_url_structure(url, ext)
                
                # Determine verdict based on rule analysis only
                if any("High Risk" in reason for reason in reasons):
                    verdict = "phishing"
                    confidence = 0.95
                elif len(reasons) > 2:
                    verdict = "phishing"
                    confidence = 0.85
                else:
                    verdict = "legitimate"
                    confidence = 0.70
                    if not reasons:
                        reasons = ["No suspicious patterns detected"]
                
                result = {
                    "url": url,
                    "verdict": verdict,
                    "confidence": float(confidence),
                    "reasons": set(reasons + ["Note: Using rule-based analysis due to model inference error"])
                }
                
                self.url_cache[url] = result
                results.append(result)
            
            return results

    async def _batch_predict(self, inputs):
        ort_inputs = {
            "input_ids": inputs["input_ids"].astype(np.int64),
            "attention_mask": inputs["attention_mask"].astype(np.int64)
        }
        return self.session.run(None, ort_inputs)[0]

    async def _batch_analyze(self, urls):
        processed_urls = self._batch_preprocess(urls)
        inputs = self._batch_tokenize(processed_urls)
        logits = await self._batch_predict(inputs)
        probabilities = np.exp(logits) / np.sum(np.exp(logits), axis=-1, keepdims=True)
        return probabilities[:, 1]

    async def analyze_batch(self, urls):
        results = []
        uncached_urls = []
        
        # Check cache first
        for url in urls:
            if url in self.url_cache:
                results.append(self.url_cache[url])
            else:
                uncached_urls.append(url)
        
        if uncached_urls:
            # Split URLs into smaller batches for multithreaded processing
            batch_size = 10  # Process 10 URLs per thread
            url_batches = [uncached_urls[i:i+batch_size] for i in range(0, len(uncached_urls), batch_size)]
            
            # Submit each batch to thread pool
            futures = []
            for batch in url_batches:
                futures.append(self.thread_pool.submit(self._predict_thread, batch))
            
            # Collect results from all threads
            for future in futures:
                try:
                    batch_results = future.result()
                    results.extend(batch_results)
                except Exception as e:
                    # Handle any unexpected errors in thread execution
                    print(f"Error processing batch: {str(e)}")
                    # Create fallback results for this batch
                    for url in batch:
                        results.append({
                            "url": url,
                            "verdict": "error",
                            "confidence": 0.0,
                            "reasons": {f"Error analyzing URL: {str(e)}"}
                        })
        
        return results

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = ONNXPhishingDetector()

class UrlList(BaseModel):
    urls: list[str]

@app.post("/scan")
async def scan_urls(url_list: UrlList):
    start_time = time.time()
    
    # Process all URLs in a single batch with internal multithreading
    results = await detector.analyze_batch(url_list.urls)
    
    phishing_count = sum(1 for r in results if r["verdict"] == "phishing")
    avg_confidence = sum(r["confidence"] for r in results) / len(results) if results else 0
    
    if avg_confidence >= 0.99:
        overall_verdict = "malicious"
    else:
        overall_verdict = "safe"
    
    return {
        "time_taken": f"{time.time() - start_time:.2f}s",
        "total_urls": len(url_list.urls),
        "legitimate": len(url_list.urls) - phishing_count,
        "phishing": phishing_count,
        "overall_verdict": overall_verdict,
        "average_confidence": avg_confidence,
        "results": results
    }

# To run this file in terminal:
# 1. Make sure you have all dependencies installed:
#    pip install fastapi uvicorn onnxruntime numpy transformers tldextract
# 2. Navigate to the directory containing this file
# 3. Run the command:
#    python -m backend.main
#    or if you're already in the backend directory:
#    python main.py
# 4. The API will be available at http://localhost:8000
# 5. You can test it with curl:
#    curl -X POST "http://localhost:8000/scan" -H "Content-Type: application/json" -d '{"urls":["google.com", "suspicious-phishing-site.xyz"]}'
# 6. Or use tools like Postman to send POST requests to the /scan endpoint

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)