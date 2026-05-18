
import sys
import os

# Add directory to path to allow import
sys.path.append(os.path.join(os.getcwd(), 'llm-agent'))

try:
    from tools import analyze_risk_statistics
    import inspect
    
    print("Successfully imported analyze_risk_statistics")
    sig = inspect.signature(analyze_risk_statistics)
    print(f"Signature: {sig}")
    
    if 'limit' in sig.parameters:
        print("Verification SUCCESS: 'limit' parameter found.")
    else:
        print("Verification FAILED: 'limit' parameter missing.")
        
except ImportError as e:
    print(f"ImportError: {e}")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
except Exception as e:
    print(f"Error: {e}")
