import numpy as np
import pytest
from core.cosine import cosine

def test_elle_hesap():
    assert abs(cosine(np.array([1, 2, 0]), np.array([2, 1, 0])) - 0.8) < 1e-9

def test_sklearn_ile_ayni():
    sk = pytest.importorskip("sklearn.metrics.pairwise")
    a, b = np.random.rand(22), np.random.rand(22)
    assert abs(cosine(a, b) - sk.cosine_similarity([a], [b])[0][0]) < 1e-9