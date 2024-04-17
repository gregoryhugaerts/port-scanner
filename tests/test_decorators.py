# Mock function for testing
import time

from port_scanner.decorators import rate_limit


def test_rate_limit_decorator():
    @rate_limit(interval=2)
    def test_function():
        return "Test"

    # Test that the function is called only once within the interval
    start_time = time.time()
    test_function()
    elapsed_time = time.time() - start_time
    assert elapsed_time < 2

    # Test that the function is called twice when called consecutively
    test_function()
    elapsed_time = time.time() - start_time
    assert elapsed_time > 2


def test_rate_limit_decorator_multiple_functions():
    @rate_limit(interval=2)
    def test_function_1():
        return "Test 1"

    @rate_limit(interval=2)
    def test_function_2():
        return "Test 2"

    # Test that each function respects its own rate limit
    start_time = time.time()
    test_function_1()
    test_function_2()
    elapsed_time = time.time() - start_time
    assert elapsed_time < 2

    # Test that calling both functions consecutively respects the rate limits
    test_function_1()
    test_function_2()
    elapsed_time = time.time() - start_time
    assert elapsed_time > 2
