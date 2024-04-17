"""Collection of decorator functions."""

import time
from collections.abc import Callable
from functools import wraps


def rate_limit(interval: int) -> Callable:
    """Rate limit a function.

    Args:
    ----
        interval (int): decorated function will only be called at most once every `interval` seconds

    """

    def decorator(func: Callable):
        last_call_times = {}

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if the function has been called before
            if func.__name__ not in last_call_times:
                last_call_times[func.__name__] = time.time()
            else:
                # Check if enough time has passed since the last call
                elapsed_time = time.time() - last_call_times[func.__name__]
                if elapsed_time < interval:
                    time.sleep(interval - elapsed_time)

            # Update the last call time
            last_call_times[func.__name__] = time.time()

            # Call the function and return the result
            return func(*args, **kwargs)

        return wrapper

    return decorator
