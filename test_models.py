#!/usr/bin/env python3
"""
Temporary script to test OpenRouter LLM model connectivity.
Tests multiple models to see which ones are available.
"""

import asyncio
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import httpx

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MODELS_TO_TEST = [
    "tngtech/deepseek-r1t2-chimera:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "tngtech/deepseek-r1t-chimera:free",
    "deepseek/deepseek-r1-0528:free",
    # Current model for comparison
    "arcee-ai/trinity-large-preview:free",
]

# Reasoning models that need longer timeouts
SLOW_MODELS = {"deepseek/deepseek-r1-0528:free", "tngtech/deepseek-r1t-chimera:free", "tngtech/deepseek-r1t2-chimera:free"}

TEST_PROMPT = "Respond with exactly one word: 'working'"


async def test_model(client: httpx.AsyncClient, model: str) -> dict:
    """Test a single model and return the result."""
    import time
    # Use longer timeout for reasoning models
    timeout = 180.0 if model in SLOW_MODELS else 60.0
    start_time = time.time()
    try:
        response = await client.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://netspecter.local",
                "X-Title": "NetSpecter Model Test",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "user", "content": TEST_PROMPT}
                ],
                "max_tokens": 50,
                "temperature": 0,
            },
            timeout=timeout,
        )
        
        if response.status_code == 200:
            elapsed = time.time() - start_time
            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            tokens = data.get("usage", {})
            return {
                "model": model,
                "status": "✅ WORKING",
                "response": content[:100],
                "prompt_tokens": tokens.get("prompt_tokens", 0),
                "completion_tokens": tokens.get("completion_tokens", 0),
                "elapsed": round(elapsed, 1),
                "error": None,
            }
        else:
            elapsed = time.time() - start_time
            error_data = response.json()
            error_msg = error_data.get("error", {}).get("message", str(response.status_code))
            return {
                "model": model,
                "status": f"❌ FAILED ({response.status_code})",
                "response": None,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "elapsed": round(elapsed, 1),
                "error": error_msg[:100],
            }
    except httpx.TimeoutException:
        timeout_used = 180 if model in SLOW_MODELS else 60
        return {
            "model": model,
            "status": "⏱️ TIMEOUT",
            "response": None,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "error": f"Request timed out after {timeout_used} seconds",
        }
    except Exception as e:
        return {
            "model": model,
            "status": "❌ ERROR",
            "response": None,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "error": str(e)[:100],
        }


async def main():
    print("=" * 70)
    print("OpenRouter LLM Model Connectivity Test")
    print("=" * 70)
    
    if not OPENROUTER_API_KEY:
        print("❌ ERROR: OPENROUTER_API_KEY not found in environment!")
        print("   Make sure you have a .env file with OPENROUTER_API_KEY set.")
        sys.exit(1)
    
    print(f"API Key: {OPENROUTER_API_KEY[:8]}...{OPENROUTER_API_KEY[-4:]}")
    print(f"Testing {len(MODELS_TO_TEST)} models...")
    print("-" * 70)
    
    results = []
    
    async with httpx.AsyncClient() as client:
        for model in MODELS_TO_TEST:
            print(f"\nTesting: {model}")
            result = await test_model(client, model)
            results.append(result)
            
            print(f"  Status: {result['status']}")
            if result['response']:
                print(f"  Response: {result['response']}")
                print(f"  Tokens: {result['prompt_tokens']} prompt + {result['completion_tokens']} completion")
                print(f"  Time: {result.get('elapsed', 'N/A')}s")
            if result['error']:
                print(f"  Error: {result['error']}")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    working = [r for r in results if "WORKING" in r['status']]
    failed = [r for r in results if "WORKING" not in r['status']]
    
    print(f"\n✅ Working Models ({len(working)}):")
    for r in working:
        print(f"   - {r['model']}")
    
    print(f"\n❌ Failed Models ({len(failed)}):")
    for r in failed:
        print(f"   - {r['model']}: {r['error']}")
    
    print("\n" + "-" * 70)
    if working:
        print("RECOMMENDATION: Use these models in config.py:")
        for r in working:
            if r['model'] != "arcee-ai/trinity-large-preview:free":
                print(f'   llm_model_stats: str = "{r["model"]}"')
                break
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
