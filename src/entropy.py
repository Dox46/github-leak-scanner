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
    """
    if len(data) < min_length:
        return False
        
    return shannon_entropy(data) >= threshold
