import numpy as np


def cosine(a, b):
    """Iki vektor arasindaki cosine similarity (sifirdan yazildi)."""
    pay = np.dot(a, b)
    payda = np.linalg.norm(a) * np.linalg.norm(b)
    if payda == 0:
        return 0.0
    return float(pay / payda)
