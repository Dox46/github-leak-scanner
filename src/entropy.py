import math
from collections import Counter

def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    High entropy means the string is highly random (like a generated secret token).
    """
    if not data:
        return 0.0
        
    probabilities = [n_x / len(data) for x, n_x in Counter(data).items()]
    return -sum(p * math.log2(p) for p in probabilities)

def is_high_entropy(data: str, threshold: float = 4.5, min_length: int = 16) -> bool:
    """
    Determine if a string appears to be a random secret based on its entropy.
    Only evaluates strings longer or equal to `min_length` to avoid false positives on short words.
    Also ensures the string contains a mix of character types (Base64/Hex like).
    """
    if len(data) < min_length:
        return False
        
    # Heuristic: A random secret usually contains a mix of digits and letters (or mixed case)
    has_digit = any(c.isdigit() for c in data)
    has_lower = any(c.islower() for c in data)
    has_upper = any(c.isupper() for c in data)
    
    # Require at least 2 different character classes
    if sum([has_digit, has_lower, has_upper]) < 2:
        return False
        
    return shannon_entropy(data) >= threshold
