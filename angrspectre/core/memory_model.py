"""
Memory model types for security analysis.
Defines structured representations of values in memory for use in vulnerability detection.
"""

class MemoryValue:
    """
    Base class for representing values in memory that can be analyzed for security properties.
    """
    def __init__(self, *, bits=64, value=None, sensitive):  # sensitive is a required keyword argument
        """
        bits: Size in bits
        value: Optional concrete or symbolic value
        sensitive: Whether this value contains sensitive data
        """
        self.bits = bits
        self.sensitive = sensitive
        self.value = value

class ScalarValue(MemoryValue):
    """
    A simple non-pointer value that may be public or sensitive
    """
    pass

class StructuredPointer(MemoryValue):
    """
    Pointer to a defined structure (scalar, array, or composite)
    """
    def __init__(self, pointee, max_size=0x10000, safe_pointer=False):
        """
        pointee: Target being pointed to (MemoryValue or list of MemoryValues)
        max_size: Upper bound on pointee size
        safe_pointer: If True, this pointer cannot access sensitive data
        """
        super().__init__(bits=64, sensitive=False)
        assert isinstance(pointee, MemoryValue) or \
            (isinstance(pointee, list) and all(isinstance(v, MemoryValue) for v in pointee))
        self.pointee = pointee
        self.max_size = max_size
        self.safe_pointer = safe_pointer

class GenericPublicPointer(MemoryValue):
    """
    Pointer to arbitrary public data (could be value, array, or structure)
    """
    def __init__(self, max_size=0x10000, safe_pointer=False):
        """
        max_size: Upper bound on pointee size
        safe_pointer: If True, this pointer cannot access sensitive data
        """
        super().__init__(bits=64, sensitive=False)
        self.max_size = max_size
        self.safe_pointer = safe_pointer

class SensitivePointer(MemoryValue):
    """
    Pointer that itself contains sensitive data (the address is sensitive)
    """
    def __init__(self):
        super().__init__(bits=64, sensitive=True)

# Factory functions for creating memory values

def create_public_value(value=None, bits=64):
    """Create a public scalar value"""
    return ScalarValue(bits=bits, value=value, sensitive=False)

def create_sensitive_value(value=None, bits=64):
    """Create a sensitive scalar value"""
    return ScalarValue(bits=bits, value=value, sensitive=True)

def create_pointer_to(pointee, max_size=0x10000, safe_pointer=False):
    """Create a pointer to a defined memory structure"""
    return StructuredPointer(pointee, max_size=max_size, safe_pointer=safe_pointer)

def create_generic_pointer(max_size=0x10000, safe_pointer=False):
    """Create a pointer to arbitrary public data"""
    return GenericPublicPointer(max_size=max_size, safe_pointer=safe_pointer)

def create_public_array(length_bytes):
    """Create an array of public values"""
    if length_bytes % 8 != 0:
        raise ValueError("Array size must be multiple of 8 bytes")
    return [create_public_value() for _ in range(length_bytes//8)]

def create_sensitive_array(length_bytes):
    """Create an array of sensitive values"""
    if length_bytes % 8 != 0:
        raise ValueError("Array size must be multiple of 8 bytes")
    return [create_sensitive_value() for _ in range(length_bytes//8)]

def create_array(values):
    """Create an array from specified values"""
    for val in values:
        assert isinstance(val, MemoryValue)
    return values

def flatten(elements):
    """Flatten nested lists into a single list"""
    result = []
    for element in elements:
        if isinstance(element, list):
            result += flatten(element)
        else:
            result.append(element)
    return result

def create_struct(elements):
    """Create a composite structure from multiple elements"""
    flattened = flatten(elements)
    for element in flattened:
        assert isinstance(element, MemoryValue)
    return flattened