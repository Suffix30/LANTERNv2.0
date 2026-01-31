import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack, BlackConfig

from integration.agent_black import (
    IntegratedAgentBlack,
    SmartProbe,
    run_smart_probe,
    print_probe_summary,
    record_scan_result,
    get_target_profile,
    get_recommended_modules,
    get_learning_summary,
    generate_improvement_report,
    apply_improvements_to_lantern,
    verify_patches_applied,
    search_flags,
    auto_decode,
    quick_solve,
    FLAG_PATTERNS,
)

__all__ = [
    'AgentBlack',
    'BlackConfig',
    'IntegratedAgentBlack',
    'SmartProbe',
    'run_smart_probe',
    'print_probe_summary',
    'record_scan_result',
    'get_target_profile',
    'get_recommended_modules',
    'get_learning_summary',
    'generate_improvement_report',
    'apply_improvements_to_lantern',
    'verify_patches_applied',
    'search_flags',
    'auto_decode',
    'quick_solve',
    'FLAG_PATTERNS',
]
