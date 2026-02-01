#!/usr/bin/env python3
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .learning import (
    ImprovementLineage,
    MeritSelector,
    GoalManager,
    SteppingStoneTracker,
    SafetyValidator,
    record_scan_result,
    get_learning_summary,
    get_lineage_summary,
)
from .smart_probe import SmartProbe, GapAnalyzer, run_gap_analysis
from .improvement_applier import (
    load_all_improvements,
    consolidate_improvements,
    generate_lantern_patch,
    test_improvement_safely,
    run_with_regression_check,
    TransferTester,
    test_transfer_across_modules,
    test_transfer_across_targets,
)
 
 
ENGINE_DIR = Path(__file__).parent / "adaptive_state"
ENGINE_DIR.mkdir(exist_ok=True)

STATE_FILE = ENGINE_DIR / "engine_state.json"
GENERATIONS_FILE = ENGINE_DIR / "generations.json"


class AdaptiveEngine:
    def __init__(self, lantern_path: Optional[Path] = None):
        self.lantern_path = lantern_path or Path(__file__).parent.parent.parent
        self.lineage = ImprovementLineage()
        self.selector = MeritSelector(self.lineage)
        self.analyzer = GapAnalyzer()
        self.goal_manager = GoalManager()
        self.stepping_stones = SteppingStoneTracker(self.lineage)
        self.safety_validator = SafetyValidator()
        self.transfer_tester = TransferTester(self.lantern_path)
        self._state = self._load_state()
    
    def _load_state(self) -> dict[str, Any]:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except:
                pass
        return {
            "generation": 0,
            "total_improvements": 0,
            "best_accuracy": 0.0,
            "last_run": None,
            "targets_scanned": [],
            "active": False,
        }
    
    def _save_state(self):
        STATE_FILE.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
    
    def run_cycle(
        self,
        target: str,
        modules: list[str] = None,
        max_improvements: int = 5,
    ) -> dict[str, Any]:
        cycle_result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "generation": self._state["generation"],
            "phases": [],
            "improvements_generated": 0,
            "improvements_applied": 0,
            "accuracy_before": 0.0,
            "accuracy_after": 0.0,
        }
        
        self._state["active"] = True
        self._state["last_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()
        
        print("\n" + "=" * 70)
        print("ADAPTIVE ENGINE - IMPROVEMENT CYCLE")
        print(f"Generation: {self._state['generation']}")
        print("=" * 70)
        
        print("\n[1/5] Running LANTERN scan...")
        lantern_result = self._run_lantern_scan(target, modules)
        cycle_result["phases"].append({
            "phase": "lantern_scan",
            "success": lantern_result.get("success", False),
            "findings_count": len(lantern_result.get("findings", [])),
        })
        
        print("\n[2/5] Running smart probe...")
        probe_result = self._run_smart_probe(target)
        cycle_result["phases"].append({
            "phase": "smart_probe",
            "success": True,
            "findings_count": probe_result.get("total_findings", 0),
        })
        
        print("\n[3/5] Analyzing gaps...")
        gap_analysis = self.analyzer.analyze_scan_gaps(
            lantern_findings=lantern_result.get("findings", []),
            probe_findings=probe_result.get("findings", []),
            target=target,
        )
        cycle_result["phases"].append({
            "phase": "gap_analysis",
            "gaps_found": gap_analysis.get("gap_count", 0),
            "proposals": len(gap_analysis.get("improvement_proposals", [])),
        })
        
        print("\n[4/5] Generating improvements...")
        improvements = self._generate_improvements(gap_analysis, max_improvements)
        cycle_result["improvements_generated"] = len(improvements)
        cycle_result["phases"].append({
            "phase": "improvement_generation",
            "improvements_generated": len(improvements),
        })
        
        print("\n[5/5] Testing and applying improvements...")
        applied = self._test_and_apply_improvements(improvements, target)
        cycle_result["improvements_applied"] = applied
        cycle_result["phases"].append({
            "phase": "improvement_application",
            "improvements_applied": applied,
        })
        
        self._state["generation"] += 1
        self._state["total_improvements"] += applied
        if target not in self._state["targets_scanned"]:
            self._state["targets_scanned"].append(target)
        self._state["active"] = False
        self._state["best_accuracy"] = self.lineage.get_best_score()
        self._save_state()
        
        self._record_generation(cycle_result)
        
        print("\n" + "=" * 70)
        print("CYCLE COMPLETE")
        print(f"Improvements Applied: {applied}")
        print(f"Best Accuracy: {self._state['best_accuracy']:.3f}")
        print("=" * 70)
        
        return cycle_result
    
    def _run_lantern_scan(self, target: str, modules: list[str] = None) -> dict[str, Any]:
        modules = modules or ["sqli", "xss", "lfi", "ssti", "cmdi", "ssrf", "headers", "secrets"]
        
        output_file = ENGINE_DIR / f"scan_{int(time.time())}"
        cmd = [
            "lantern", "-t", target,
            "-m", ",".join(modules),
            "--format", "json",
            "-o", str(output_file),
            "--quiet"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.lantern_path),
                encoding="utf-8",
                errors="replace"
            )
            
            json_file = Path(str(output_file) + ".json")
            if json_file.exists():
                report = json.loads(json_file.read_text(encoding="utf-8"))
                findings = report.get("findings", [])
                
                findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                successful_exploits = []
                for f in findings:
                    sev = f.get("severity", "INFO")
                    findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
                    if f.get("exploited") or f.get("confirmed"):
                        successful_exploits.append(f)
                
                record_scan_result(
                    target=target,
                    modules_used=modules,
                    findings=findings_by_severity,
                    flags_found=[],
                    successful_exploits=successful_exploits,
                    tech_detected=report.get("tech_detected", []),
                )
                
                return {
                    "success": True,
                    "findings": findings,
                    "modules_used": modules,
                }
            
            return {"success": False, "findings": [], "error": "No output file"}
            
        except Exception as e:
            return {"success": False, "findings": [], "error": str(e)}
    
    def _run_smart_probe(self, target: str) -> dict[str, Any]:
        try:
            probe = SmartProbe(target)
            return probe.probe_all()
        except Exception as e:
            return {"total_findings": 0, "findings": [], "error": str(e)}
    
    def _generate_improvements(
        self,
        gap_analysis: dict[str, Any],
        max_count: int,
    ) -> list[dict[str, Any]]:
        improvements = []
        
        proposals = gap_analysis.get("improvement_proposals", [])
        diagnosis = gap_analysis.get("structured_diagnosis") or {}
        
        for impl_suggestion in diagnosis.get("implementation_suggestions", [])[:max_count]:
            code_template = impl_suggestion.get("code_template", "")
            if not code_template:
                continue
            
            target_file = impl_suggestion.get("target_file", "")
            module = target_file.replace("modules/", "").replace(".py", "")
            
            patch = self._code_to_patch(code_template, target_file)
            
            improvements.append({
                "module": module,
                "target_file": target_file,
                "code_changes": code_template,
                "patch_content": patch,
                "description": f"Gap analysis improvement for {module}",
            })
        
        return improvements
    
    def _code_to_patch(self, code: str, target_file: str) -> str:
        lines = code.split("\n")
        patch_lines = [
            f"--- a/{target_file}",
            f"+++ b/{target_file}",
            "@@ -1,0 +1,{len(lines)} @@",
        ]
        for line in lines:
            patch_lines.append(f"+{line}")
        return "\n".join(patch_lines)
    
    def _test_and_apply_improvements(
        self,
        improvements: list[dict[str, Any]],
        test_target: str,
    ) -> int:
        applied_count = 0
        
        for improvement in improvements:
            patch_content = improvement.get("patch_content", "")
            if not patch_content:
                continue
            
            print(f"  Testing: {improvement.get('module', 'unknown')}...")
            
            result = run_with_regression_check(
                patch_content=patch_content,
                lantern_path=self.lantern_path,
                test_target=test_target,
            )
            
            if result.get("added_to_lineage"):
                applied_count += 1
                print(f"    ✓ Applied (ID: {result.get('improvement_id', 'N/A')})")
            else:
                print(f"    ✗ Rejected: {result.get('rejection_reason', 'Unknown')}")
        
        return applied_count
    
    def _record_generation(self, cycle_result: dict[str, Any]):
        generations = []
        if GENERATIONS_FILE.exists():
            try:
                generations = json.loads(GENERATIONS_FILE.read_text(encoding="utf-8"))
            except:
                pass
        
        generations.append(cycle_result)
        GENERATIONS_FILE.write_text(json.dumps(generations, indent=2), encoding="utf-8")
    
    def run_continuous(
        self,
        targets: list[str],
        generations: int = 10,
        sleep_between: int = 60,
    ) -> dict[str, Any]:
        results = []
        
        for gen in range(generations):
            target = targets[gen % len(targets)]
            print(f"\n{'='*70}")
            print(f"CONTINUOUS MODE - Generation {gen + 1}/{generations}")
            print(f"Target: {target}")
            print(f"{'='*70}")
            
            result = self.run_cycle(target)
            results.append(result)
            
            if gen < generations - 1:
                print(f"\nSleeping {sleep_between}s before next generation...")
                time.sleep(sleep_between)
        
        return {
            "generations_run": len(results),
            "total_improvements": sum(r.get("improvements_applied", 0) for r in results),
            "final_accuracy": self.lineage.get_best_score(),
            "results": results,
        }
    
    def get_status(self) -> dict[str, Any]:
        return {
            "state": self._state,
            "lineage_summary": {
                "total_nodes": len(self.lineage.get_all_nodes()),
                "best_score": self.lineage.get_best_score(),
                "best_node": self.lineage.get_best_node_id(),
                "generations": self.lineage.get_generation_count(),
            },
            "next_parent_candidates": self.selector.get_selection_probabilities()[:5],
        }
    
    def select_next_parent(self, method: str = "merit_weighted") -> str:
        return self.selector.select_parent(method)
    
    def review_pending_improvements(self) -> dict[str, Any]:
        all_improvements = load_all_improvements()
        consolidated = consolidate_improvements(all_improvements)
        
        return {
            "total_improvements": len(all_improvements),
            "by_type": {k: len(v) for k, v in consolidated.items()},
            "improvements": consolidated,
        }
    
    def generate_patches_for_type(self, finding_type: str) -> Optional[dict[str, Any]]:
        all_improvements = load_all_improvements()
        consolidated = consolidate_improvements(all_improvements)
        
        type_improvements = consolidated.get(finding_type, [])
        if not type_improvements:
            return None
        
        return generate_lantern_patch(finding_type, type_improvements)
    
    def quick_test_improvement(self, patch_content: str, test_target: Optional[str] = None) -> dict[str, Any]:
        return test_improvement_safely(patch_content, test_target)
    
    def run_gap_analysis_only(self, target: str) -> dict[str, Any]:
        return run_gap_analysis(target)
    
    def switch_goal_if_needed(self) -> Optional[str]:
        archive = self.lineage._archive
        recent = archive.get("improvements", [])[-10:]
        
        new_goal = self.goal_manager.should_switch_goal(recent)
        if new_goal:
            current = self.goal_manager.get_active_goal()
            self.goal_manager.switch_goal(new_goal, f"Auto-switch from {current} due to stagnation")
            return new_goal
        return None
    
    def get_exploration_candidates(self) -> list[str]:
        self.stepping_stones.identify_breakthrough_ancestors()
        return self.stepping_stones.get_exploration_candidates()
    
    def validate_improvement_safety(
        self,
        improvement: dict[str, Any],
        accuracy_before: float,
        accuracy_after: float,
    ) -> bool:
        return self.safety_validator.is_improvement_safe(improvement, accuracy_before, accuracy_after)
    
    def test_improvement_transfer(
        self,
        patch_content: str,
        source_module: str,
        test_target: Optional[str] = None,
    ) -> dict[str, Any]:
        return self.transfer_tester.test_cross_module_transfer(
            patch_content, source_module, 
            ["sqli", "xss", "lfi", "ssti", "cmdi"], 
            test_target
        )
    
    def test_module_transfer(
        self,
        patch_content: str,
        source_module: str,
        test_target: Optional[str] = None,
    ) -> dict[str, Any]:
        return test_transfer_across_modules(patch_content, source_module, test_target)
    
    def test_target_transfer(
        self,
        patch_content: str,
        source_target: str,
        test_targets: list[str],
    ) -> dict[str, Any]:
        return test_transfer_across_targets(patch_content, source_target, test_targets)
    
    def run_branching_exploration(
        self,
        target: str,
        num_branches: int = 3,
    ) -> dict[str, Any]:
        results = {
            "branches": [],
            "best_branch": None,
            "best_score": 0.0,
        }
        
        candidates = self.get_exploration_candidates()
        if not candidates:
            candidates = ["initial"]
        
        import random
        selected = random.sample(candidates, min(num_branches, len(candidates)))
        
        for parent_id in selected:
            print(f"\n  Exploring branch from: {parent_id}")
            
            branch_result = {
                "parent": parent_id,
                "improvements": [],
                "final_score": 0.0,
            }
            
            gap_analysis = self.run_gap_analysis_only(target)
            improvements = self._generate_improvements(gap_analysis, max_count=2)
            
            for imp in improvements:
                test_result = run_with_regression_check(
                    patch_content=imp.get("patch_content", ""),
                    lantern_path=self.lantern_path,
                    test_target=target,
                )
                
                if test_result.get("added_to_lineage"):
                    branch_result["improvements"].append(test_result.get("improvement_id"))
                    branch_result["final_score"] = test_result.get("accuracy_after", 0)
            
            results["branches"].append(branch_result)
            
            if branch_result["final_score"] > results["best_score"]:
                results["best_score"] = branch_result["final_score"]
                results["best_branch"] = parent_id
        
        return results
    
    def get_full_status(self) -> dict[str, Any]:
        base_status = self.get_status()
        
        base_status["goal"] = {
            "active": self.goal_manager.get_active_goal(),
            "weight": self.goal_manager.get_goal_weight(),
        }
        
        base_status["safety"] = self.safety_validator.get_safety_summary()
        
        base_status["transfer"] = self.transfer_tester.get_transfer_summary()
        
        base_status["stepping_stones"] = {
            "candidates": len(self.get_exploration_candidates()),
            "breakthrough_ancestors": len(self.stepping_stones._stones.get("breakthrough_ancestors", [])),
        }
        
        return base_status


def run_adaptive_cycle(target: str, modules: list[str] = None) -> dict[str, Any]:
    engine = AdaptiveEngine()
    return engine.run_cycle(target, modules)


def get_engine_status() -> dict[str, Any]:
    engine = AdaptiveEngine()
    return engine.get_status()


def print_engine_status(include_learning: bool = True, include_lineage: bool = True) -> str:
    status = get_engine_status()
    
    lines = [
        "",
        "=" * 70,
        "ADAPTIVE ENGINE STATUS",
        "=" * 70,
        "",
        f"Generation: {status['state'].get('generation', 0)}",
        f"Total Improvements: {status['state'].get('total_improvements', 0)}",
        f"Best Accuracy: {status['state'].get('best_accuracy', 0):.3f}",
        f"Last Run: {status['state'].get('last_run', 'Never')}",
        f"Active: {status['state'].get('active', False)}",
        "",
        "LINEAGE:",
        f"  Nodes: {status['lineage_summary'].get('total_nodes', 0)}",
        f"  Best Score: {status['lineage_summary'].get('best_score', 0):.3f}",
        f"  Best Node: {status['lineage_summary'].get('best_node', 'initial')}",
        "",
        "NEXT PARENT CANDIDATES:",
    ]
    
    for node_id, prob in status.get("next_parent_candidates", []):
        lines.append(f"  {node_id}: {prob*100:.1f}%")
    
    lines.append("")
    lines.append("=" * 70)
    
    if include_learning:
        lines.append("")
        lines.append(get_learning_summary())
    
    if include_lineage:
        lines.append("")
        lines.append(get_lineage_summary())
    
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Agent BLACK Adaptive Engine")
    parser.add_argument("--target", "-t", help="Target URL")
    parser.add_argument("--modules", "-m", help="Comma-separated modules")
    parser.add_argument("--status", action="store_true", help="Show engine status")
    parser.add_argument("--continuous", type=int, help="Run N generations")
    args = parser.parse_args()
    
    if args.status:
        print(print_engine_status())
    elif args.target:
        modules = args.modules.split(",") if args.modules else None
        if args.continuous:
            engine = AdaptiveEngine()
            result = engine.run_continuous([args.target], generations=args.continuous)
            print(f"\nFinal accuracy: {result['final_accuracy']:.3f}")
        else:
            result = run_adaptive_cycle(args.target, modules)
            print(f"\nImprovements applied: {result['improvements_applied']}")
    else:
        print(print_engine_status())
