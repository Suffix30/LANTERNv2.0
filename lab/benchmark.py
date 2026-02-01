#!/usr/bin/env python3
import json
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


BENCHMARK_DIR = Path(__file__).parent / "benchmark_results"
BENCHMARK_DIR.mkdir(exist_ok=True)


@dataclass
class BenchmarkTarget:
    name: str
    url: str
    expected_vulns: list[str]
    expected_modules: list[str]
    severity_weights: dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "INFO": 0.1
    })
    timeout: int = 120
    tags: list[str] = field(default_factory=list)


BENCHMARK_TARGETS = [
    BenchmarkTarget(
        name="DVWA_SQLi",
        url="http://localhost:8080/vulnerabilities/sqli/",
        expected_vulns=["sqli"],
        expected_modules=["sqli"],
        tags=["injection", "basic"]
    ),
    BenchmarkTarget(
        name="DVWA_XSS_Reflected",
        url="http://localhost:8080/vulnerabilities/xss_r/",
        expected_vulns=["xss_reflected"],
        expected_modules=["xss"],
        tags=["xss", "basic"]
    ),
    BenchmarkTarget(
        name="DVWA_LFI",
        url="http://localhost:8080/vulnerabilities/fi/",
        expected_vulns=["lfi", "path_traversal"],
        expected_modules=["lfi"],
        tags=["lfi", "basic"]
    ),
    BenchmarkTarget(
        name="DVWA_CSRF",
        url="http://localhost:8080/vulnerabilities/csrf/",
        expected_vulns=["csrf"],
        expected_modules=["csrf"],
        tags=["csrf", "basic"]
    ),
    BenchmarkTarget(
        name="DVWA_CMDi",
        url="http://localhost:8080/vulnerabilities/exec/",
        expected_vulns=["command_injection"],
        expected_modules=["cmdi"],
        tags=["rce", "basic"]
    ),
    BenchmarkTarget(
        name="JuiceShop_SQLi",
        url="http://localhost:3000/rest/products/search",
        expected_vulns=["sqli"],
        expected_modules=["sqli"],
        tags=["injection", "api"]
    ),
    BenchmarkTarget(
        name="JuiceShop_XSS",
        url="http://localhost:3000/#/search",
        expected_vulns=["xss_dom", "xss_reflected"],
        expected_modules=["xss", "dom"],
        tags=["xss", "spa"]
    ),
    BenchmarkTarget(
        name="JuiceShop_IDOR",
        url="http://localhost:3000/api/BasketItems/",
        expected_vulns=["idor"],
        expected_modules=["idor", "accessctl"],
        tags=["auth", "api"]
    ),
    BenchmarkTarget(
        name="SecureBank_Headers",
        url="http://localhost:5000/",
        expected_vulns=["missing_headers", "cors"],
        expected_modules=["headers", "cors"],
        tags=["config", "basic"]
    ),
    BenchmarkTarget(
        name="SecureBank_Disclosure",
        url="http://localhost:5000/",
        expected_vulns=["information_disclosure", "sensitive_files"],
        expected_modules=["disclosure", "secrets"],
        tags=["disclosure", "basic"]
    ),
]


@dataclass
class BenchmarkResult:
    target: BenchmarkTarget
    detected_vulns: list[str]
    detected_modules: list[str]
    findings_count: int
    severity_counts: dict[str, int]
    true_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy_score: float
    scan_duration: float
    timestamp: str
    error: Optional[str] = None


class DetectionBenchmark:
    def __init__(self, lantern_path: str = "lantern", targets: list[BenchmarkTarget] = None):
        self.lantern_path = lantern_path
        self.targets = targets or BENCHMARK_TARGETS
        self.results: list[BenchmarkResult] = []
    
    def run_all(self, parallel: int = 1, tags_filter: list[str] = None) -> dict[str, Any]:
        targets = self.targets
        if tags_filter:
            targets = [t for t in targets if any(tag in t.tags for tag in tags_filter)]
        
        start_time = time.time()
        
        if parallel > 1:
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {executor.submit(self._run_single, target): target for target in targets}
                for future in as_completed(futures):
                    result = future.result()
                    self.results.append(result)
        else:
            for target in targets:
                result = self._run_single(target)
                self.results.append(result)
        
        total_duration = time.time() - start_time
        
        return self._compile_report(total_duration)
    
    def _run_single(self, target: BenchmarkTarget) -> BenchmarkResult:
        print(f"[Benchmark] Testing: {target.name}")
        
        start = time.time()
        output_file = BENCHMARK_DIR / f"scan_{target.name}_{int(time.time())}"
        
        cmd = [
            self.lantern_path, "-t", target.url,
            "-m", ",".join(target.expected_modules),
            "--format", "json",
            "-o", str(output_file),
            "--quiet"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=target.timeout,
                encoding="utf-8",
                errors="replace"
            )
            scan_duration = time.time() - start
            
            json_file = Path(str(output_file) + ".json")
            if json_file.exists():
                report = json.loads(json_file.read_text(encoding="utf-8"))
                findings = report.get("findings", [])
            else:
                findings = self._parse_stdout_findings(result.stdout)
            
            return self._calculate_metrics(target, findings, scan_duration)
            
        except subprocess.TimeoutExpired:
            return BenchmarkResult(
                target=target,
                detected_vulns=[],
                detected_modules=[],
                findings_count=0,
                severity_counts={},
                true_positives=0,
                false_negatives=len(target.expected_vulns),
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                accuracy_score=0.0,
                scan_duration=target.timeout,
                timestamp=datetime.now(timezone.utc).isoformat(),
                error="Timeout"
            )
        except Exception as e:
            return BenchmarkResult(
                target=target,
                detected_vulns=[],
                detected_modules=[],
                findings_count=0,
                severity_counts={},
                true_positives=0,
                false_negatives=len(target.expected_vulns),
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                accuracy_score=0.0,
                scan_duration=time.time() - start,
                timestamp=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
    
    def _parse_stdout_findings(self, stdout: str) -> list[dict[str, Any]]:
        findings = []
        return findings
    
    def _calculate_metrics(
        self,
        target: BenchmarkTarget,
        findings: list[dict[str, Any]],
        scan_duration: float
    ) -> BenchmarkResult:
        detected_modules = list(set(f.get("module", "unknown") for f in findings))
        detected_vulns = list(set(f.get("type", f.get("module", "unknown")) for f in findings))
        
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        expected_set = set(target.expected_modules)
        detected_set = set(detected_modules)
        
        true_positives = len(expected_set & detected_set)
        false_negatives = len(expected_set - detected_set)
        false_positives = len(detected_set - expected_set)
        
        precision = true_positives / max(true_positives + false_positives, 1)
        recall = true_positives / max(true_positives + false_negatives, 1)
        f1_score = 2 * precision * recall / max(precision + recall, 0.001)
        
        weighted_score = 0.0
        for finding in findings:
            sev = finding.get("severity", "INFO")
            weight = target.severity_weights.get(sev, 0.1)
            if finding.get("module") in expected_set:
                weighted_score += weight
        
        max_possible = len(expected_set) * max(target.severity_weights.values())
        accuracy_score = weighted_score / max(max_possible, 1)
        
        return BenchmarkResult(
            target=target,
            detected_vulns=detected_vulns,
            detected_modules=detected_modules,
            findings_count=len(findings),
            severity_counts=severity_counts,
            true_positives=true_positives,
            false_negatives=false_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy_score=min(accuracy_score, 1.0),
            scan_duration=scan_duration,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def _compile_report(self, total_duration: float) -> dict[str, Any]:
        total_tp = sum(r.true_positives for r in self.results)
        total_fn = sum(r.false_negatives for r in self.results)
        avg_precision = sum(r.precision for r in self.results) / max(len(self.results), 1)
        avg_recall = sum(r.recall for r in self.results) / max(len(self.results), 1)
        avg_f1 = sum(r.f1_score for r in self.results) / max(len(self.results), 1)
        avg_accuracy = sum(r.accuracy_score for r in self.results) / max(len(self.results), 1)
        
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_duration": total_duration,
            "targets_tested": len(self.results),
            "aggregate_metrics": {
                "total_true_positives": total_tp,
                "total_false_negatives": total_fn,
                "average_precision": avg_precision,
                "average_recall": avg_recall,
                "average_f1_score": avg_f1,
                "overall_accuracy": avg_accuracy,
            },
            "results_by_target": [
                {
                    "name": r.target.name,
                    "url": r.target.url,
                    "expected": r.target.expected_modules,
                    "detected": r.detected_modules,
                    "precision": r.precision,
                    "recall": r.recall,
                    "f1_score": r.f1_score,
                    "accuracy_score": r.accuracy_score,
                    "findings_count": r.findings_count,
                    "duration": r.scan_duration,
                    "error": r.error,
                }
                for r in self.results
            ],
            "by_category": self._aggregate_by_tag(),
        }
        
        report_file = BENCHMARK_DIR / f"benchmark_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        
        return report
    
    def _aggregate_by_tag(self) -> dict[str, dict[str, float]]:
        by_tag: dict[str, list[BenchmarkResult]] = {}
        
        for result in self.results:
            for tag in result.target.tags:
                if tag not in by_tag:
                    by_tag[tag] = []
                by_tag[tag].append(result)
        
        aggregated = {}
        for tag, results in by_tag.items():
            aggregated[tag] = {
                "count": len(results),
                "avg_precision": sum(r.precision for r in results) / len(results),
                "avg_recall": sum(r.recall for r in results) / len(results),
                "avg_f1": sum(r.f1_score for r in results) / len(results),
                "avg_accuracy": sum(r.accuracy_score for r in results) / len(results),
            }
        
        return aggregated
    
    def get_accuracy_score(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.accuracy_score for r in self.results) / len(self.results)


def run_benchmark(tags: list[str] = None, parallel: int = 1) -> dict[str, Any]:
    benchmark = DetectionBenchmark()
    return benchmark.run_all(parallel=parallel, tags_filter=tags)


def get_latest_benchmark() -> Optional[dict[str, Any]]:
    results = sorted(BENCHMARK_DIR.glob("benchmark_*.json"), reverse=True)
    if results:
        return json.loads(results[0].read_text(encoding="utf-8"))
    return None


def compare_benchmarks(before_file: Path, after_file: Path) -> dict[str, Any]:
    before = json.loads(before_file.read_text(encoding="utf-8"))
    after = json.loads(after_file.read_text(encoding="utf-8"))
    
    before_acc = before.get("aggregate_metrics", {}).get("overall_accuracy", 0)
    after_acc = after.get("aggregate_metrics", {}).get("overall_accuracy", 0)
    
    comparison = {
        "before_accuracy": before_acc,
        "after_accuracy": after_acc,
        "accuracy_delta": after_acc - before_acc,
        "improved": after_acc > before_acc,
        "before_timestamp": before.get("timestamp"),
        "after_timestamp": after.get("timestamp"),
        "by_target": [],
    }
    
    before_by_name = {r["name"]: r for r in before.get("results_by_target", [])}
    after_by_name = {r["name"]: r for r in after.get("results_by_target", [])}
    
    for name in set(before_by_name.keys()) | set(after_by_name.keys()):
        b = before_by_name.get(name, {})
        a = after_by_name.get(name, {})
        comparison["by_target"].append({
            "name": name,
            "before_accuracy": b.get("accuracy_score", 0),
            "after_accuracy": a.get("accuracy_score", 0),
            "delta": a.get("accuracy_score", 0) - b.get("accuracy_score", 0),
        })
    
    return comparison


def print_benchmark_report(report: dict[str, Any]) -> str:
    lines = [
        "",
        "=" * 70,
        "LANTERN DETECTION BENCHMARK REPORT",
        "=" * 70,
        "",
        f"Timestamp: {report.get('timestamp', 'N/A')}",
        f"Duration: {report.get('total_duration', 0):.1f}s",
        f"Targets Tested: {report.get('targets_tested', 0)}",
        "",
        "AGGREGATE METRICS:",
        f"  Overall Accuracy: {report.get('aggregate_metrics', {}).get('overall_accuracy', 0)*100:.1f}%",
        f"  Average Precision: {report.get('aggregate_metrics', {}).get('average_precision', 0)*100:.1f}%",
        f"  Average Recall: {report.get('aggregate_metrics', {}).get('average_recall', 0)*100:.1f}%",
        f"  Average F1 Score: {report.get('aggregate_metrics', {}).get('average_f1_score', 0)*100:.1f}%",
        "",
        "RESULTS BY TARGET:",
    ]
    
    for result in report.get("results_by_target", []):
        status = "✅" if result.get("accuracy_score", 0) > 0.5 else "⚠️" if result.get("accuracy_score", 0) > 0 else "❌"
        lines.append(f"  {status} {result.get('name', 'Unknown')}: {result.get('accuracy_score', 0)*100:.1f}%")
        if result.get("error"):
            lines.append(f"      Error: {result.get('error')}")
    
    lines.append("")
    lines.append("BY CATEGORY:")
    for tag, metrics in report.get("by_category", {}).items():
        lines.append(f"  [{tag}] Accuracy: {metrics.get('avg_accuracy', 0)*100:.1f}% ({metrics.get('count', 0)} targets)")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="LANTERN Detection Benchmark")
    parser.add_argument("--tags", nargs="+", help="Filter by tags")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel workers")
    parser.add_argument("--compare", nargs=2, help="Compare two benchmark files")
    args = parser.parse_args()
    
    if args.compare:
        comparison = compare_benchmarks(Path(args.compare[0]), Path(args.compare[1]))
        print(f"Accuracy change: {comparison['accuracy_delta']*100:+.1f}%")
        print(f"Improved: {comparison['improved']}")
    else:
        report = run_benchmark(tags=args.tags, parallel=args.parallel)
        print(print_benchmark_report(report))
