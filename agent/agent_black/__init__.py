try:
    from .main import main
except ImportError:
    main = None
  
try:
    from .learning import (
        ImprovementLineage,
        MeritSelector,
        GoalManager,
        SteppingStoneTracker,
        SafetyValidator,
        record_scan_result,
        record_module_effectiveness,
        record_successful_payload,
        get_target_profile,
        get_recommended_modules,
        get_prioritized_payloads,
        get_learning_summary,
        get_lineage_summary,
    )
except ImportError:
    ImprovementLineage = None
    MeritSelector = None
    GoalManager = None
    SteppingStoneTracker = None
    SafetyValidator = None

try:
    from .smart_probe import SmartProbe, GapAnalyzer, run_gap_analysis
except ImportError:
    SmartProbe = None
    GapAnalyzer = None

try:
    from .improvement_applier import (
        IsolatedTester,
        TransferTester,
        test_improvement_safely,
        run_with_regression_check,
        test_transfer_across_modules,
        test_transfer_across_targets,
    )
except ImportError:
    IsolatedTester = None
    TransferTester = None

try:
    from .adaptive_engine import AdaptiveEngine, run_adaptive_cycle, get_engine_status
except ImportError:
    AdaptiveEngine = None

try:
    from .visualize import LineageVisualizer, VISUALIZATION_DIR
except ImportError:
    LineageVisualizer = None
    VISUALIZATION_DIR = None

from .ctf_utils import (
    FLAG_PATTERNS,
    detect_encoding,
    decode_base64,
    decode_hex,
    decode_hex_safe,
    decode_binary,
    decode_url,
    decode_base32,
    rot_decode,
    try_all_rot,
    xor_decode,
    xor_single_byte_attack,
    xor_multi_byte_attack,
    auto_decode,
    search_flags,
    add_flag_pattern,
    identify_hash,
    hash_string,
    crack_hash_wordlist,
    analyze_binary_file,
    extract_strings,
    analyze_js_source,
    analyze_html_source,
    frequency_analysis,
    substitution_cipher_hint,
    vigenere_decrypt,
    caesar_bruteforce,
    atbash_decode,
    morse_decode,
    bacon_decode,
    rail_fence_decode,
    run_command,
    run_external_tool,
    quick_solve,
    solve_web_challenge,
    encode_url,
    encode_base64,
    encode_hex,
    write_to_temp,
    get_env_hints,
    save_session,
    load_session,
    load_challenge_file,
    export_findings,
    print_ctf_summary,
)

__all__ = [
    "main",
    "ImprovementLineage",
    "MeritSelector",
    "GoalManager",
    "SteppingStoneTracker",
    "SafetyValidator",
    "SmartProbe",
    "GapAnalyzer",
    "IsolatedTester",
    "TransferTester",
    "AdaptiveEngine",
    "LineageVisualizer",
    "VISUALIZATION_DIR",
    "run_adaptive_cycle",
    "get_engine_status",
    "run_gap_analysis",
    "test_improvement_safely",
    "run_with_regression_check",
    "test_transfer_across_modules",
    "test_transfer_across_targets",
    "record_scan_result",
    "record_module_effectiveness",
    "record_successful_payload",
    "get_target_profile",
    "get_recommended_modules",
    "get_prioritized_payloads",
    "get_learning_summary",
    "get_lineage_summary",
    "FLAG_PATTERNS",
    "detect_encoding",
    "decode_base64",
    "decode_hex",
    "decode_hex_safe",
    "decode_binary",
    "decode_url",
    "decode_base32",
    "rot_decode",
    "try_all_rot",
    "xor_decode",
    "xor_single_byte_attack",
    "xor_multi_byte_attack",
    "auto_decode",
    "search_flags",
    "add_flag_pattern",
    "identify_hash",
    "hash_string",
    "crack_hash_wordlist",
    "analyze_binary_file",
    "extract_strings",
    "analyze_js_source",
    "analyze_html_source",
    "frequency_analysis",
    "substitution_cipher_hint",
    "vigenere_decrypt",
    "caesar_bruteforce",
    "atbash_decode",
    "morse_decode",
    "bacon_decode",
    "rail_fence_decode",
    "run_command",
    "run_external_tool",
    "quick_solve",
    "solve_web_challenge",
    "encode_url",
    "encode_base64",
    "encode_hex",
    "write_to_temp",
    "get_env_hints",
    "save_session",
    "load_session",
    "load_challenge_file",
    "export_findings",
    "print_ctf_summary",
]
