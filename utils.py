import time
import functools


class StatRecorder(object):
    _recorded_methods = {}

    @staticmethod
    def method_recorder(func):
        """
        A wrapper, counting the amount of times a method has been called,
        and the total amount of time all of it's runs took.
        :param func: the method to measure
        """

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if func.__name__ not in StatRecorder._recorded_methods:
                StatRecorder._recorded_methods[func.__name__] = {'method_count': 0, 'total_method_time': 0}
            start_time = time.time()
            value = func(*args, **kwargs)
            end_time = time.time()
            method_time = end_time - start_time
            print(method_time)
            StatRecorder._recorded_methods[func.__name__]['method_count'] += 1
            StatRecorder._recorded_methods[func.__name__]['total_method_time'] += method_time
            return value

        return wrapper

    @staticmethod
    def get_method_stats(method: str) -> dict:
        """
        Returns the specified method's recorded stats.
        These include the number of times it was called, and the total time it took.

        :param method: the name of the method whose info should be returned.
        """
        try:
            return {
                'method_count': StatRecorder._recorded_methods[method]['method_count'],
                'total_method_time': StatRecorder._recorded_methods[method]['total_method_time']
            }
        except KeyError:
            return {'method_count': 0, 'total_method_time': 0}
