import pytest
from calc import add, divide, subtract

def test_add():
    """Validates REQ-001: Addition of numbers."""
    assert add(2, 3) == 5

def test_subtract():
    """Validates REQ-002: Subtraction of numbers."""
    assert subtract(5, 2) == 3

def test_divide():
    """Validates REQ-003: Division by zero raises ValueError."""
    assert divide(6, 2) == 3
    with pytest.raises(ValueError):
        divide(1, 0)
