try:
    from .benchmark import (
        BenchmarkTarget,
        DetectionBenchmark,
        run_benchmark,
        get_latest_benchmark,
        compare_benchmarks,
        print_benchmark_report,
    )
except ImportError:
    BenchmarkTarget = None
    DetectionBenchmark = None

__all__ = [
    "BenchmarkTarget",
    "DetectionBenchmark",
    "run_benchmark",
    "get_latest_benchmark",
    "compare_benchmarks",
    "print_benchmark_report",
]
