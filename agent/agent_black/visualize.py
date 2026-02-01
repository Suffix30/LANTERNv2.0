#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .learning import ImprovementLineage, LEARNING_DIR


VISUALIZATION_DIR = Path(__file__).parent / "visualizations"
VISUALIZATION_DIR.mkdir(exist_ok=True)


class LineageVisualizer:
    def __init__(self):
        self.lineage = ImprovementLineage()
    
    def generate_ascii_tree(self) -> str:
        nodes = self.lineage.get_all_nodes()
        
        if len(nodes) <= 1:
            return "No improvements recorded yet.\n[initial] (baseline)"
        
        children_map: dict[str, list[str]] = {"initial": []}
        for node in nodes:
            if node["id"] != "initial":
                parent = node.get("parent", "initial")
                if parent not in children_map:
                    children_map[parent] = []
                children_map[parent].append(node["id"])
        
        lines = [
            "IMPROVEMENT LINEAGE TREE",
            "=" * 50,
            "",
        ]
        
        def render_node(node_id: str, prefix: str, is_last: bool) -> list[str]:
            node = self.lineage.get_node(node_id)
            if not node:
                return []
            
            connector = "└── " if is_last else "├── "
            score = node.get("accuracy_score", 0.0)
            best_marker = " ★" if node_id == self.lineage.get_best_node_id() else ""
            
            result = [f"{prefix}{connector}{node_id} (score: {score:.3f}){best_marker}"]
            
            children = children_map.get(node_id, [])
            child_prefix = prefix + ("    " if is_last else "│   ")
            
            for i, child_id in enumerate(children):
                is_child_last = i == len(children) - 1
                result.extend(render_node(child_id, child_prefix, is_child_last))
            
            return result
        
        root_score = self.lineage._lineage["root"].get("accuracy_score", 0.0)
        best_marker = " ★" if self.lineage.get_best_node_id() == "initial" else ""
        lines.append(f"[initial] (score: {root_score:.3f}){best_marker}")
        
        root_children = children_map.get("initial", [])
        for i, child_id in enumerate(root_children):
            is_last = i == len(root_children) - 1
            lines.extend(render_node(child_id, "", is_last))
        
        lines.extend([
            "",
            "★ = Best performing node",
            "",
        ])
        
        return "\n".join(lines)
    
    def generate_html_tree(self, output_path: Optional[Path] = None) -> str:
        nodes = self.lineage.get_all_nodes()
        best_id = self.lineage.get_best_node_id()
        
        nodes_data = []
        edges_data = []
        
        for node in nodes:
            node_id = node["id"]
            score = node.get("accuracy_score", 0.0)
            is_best = node_id == best_id
            
            color = "#4CAF50" if is_best else (
                "#2196F3" if score > 0.5 else (
                    "#FFC107" if score > 0.2 else "#9E9E9E"
                )
            )
            
            nodes_data.append({
                "id": node_id,
                "label": f"{node_id[:15]}\n{score:.3f}",
                "color": color,
                "size": 30 if is_best else 20,
            })
            
            parent = node.get("parent")
            if parent:
                edges_data.append({"from": parent, "to": node_id})
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Agent BLACK - Improvement Lineage</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }}
        h1 {{ color: #4CAF50; }}
        #network {{ width: 100%; height: 600px; border: 1px solid #333; background: #2a2a2a; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #333; padding: 15px; border-radius: 8px; min-width: 150px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #4CAF50; }}
        .stat-label {{ color: #888; font-size: 12px; }}
        .legend {{ display: flex; gap: 15px; margin-top: 10px; }}
        .legend-item {{ display: flex; align-items: center; gap: 5px; }}
        .legend-color {{ width: 12px; height: 12px; border-radius: 50%; }}
    </style>
</head>
<body>
    <h1>🧠 Agent BLACK - Improvement Lineage</h1>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{len(nodes)}</div>
            <div class="stat-label">Total Nodes</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{self.lineage.get_best_score():.3f}</div>
            <div class="stat-label">Best Score</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{self.lineage.get_generation_count()}</div>
            <div class="stat-label">Generations</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{best_id[:12]}...</div>
            <div class="stat-label">Best Node</div>
        </div>
    </div>
    
    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background:#4CAF50"></div> Best</div>
        <div class="legend-item"><div class="legend-color" style="background:#2196F3"></div> High (&gt;0.5)</div>
        <div class="legend-item"><div class="legend-color" style="background:#FFC107"></div> Medium (&gt;0.2)</div>
        <div class="legend-item"><div class="legend-color" style="background:#9E9E9E"></div> Low</div>
    </div>
    
    <div id="network"></div>
    
    <script>
        var nodes = {json.dumps(nodes_data)};
        var edges = {json.dumps(edges_data)};
        
        var container = document.getElementById('network');
        
        function drawNetwork() {{
            var canvas = document.createElement('canvas');
            canvas.width = container.clientWidth;
            canvas.height = 600;
            container.appendChild(canvas);
            var ctx = canvas.getContext('2d');
            
            var positions = {{}};
            var levelMap = {{}};
            
            function getLevel(nodeId, visited) {{
                if (visited.has(nodeId)) return 0;
                visited.add(nodeId);
                var node = nodes.find(n => n.id === nodeId);
                if (!node) return 0;
                var parent = edges.find(e => e.to === nodeId);
                if (!parent) return 0;
                return 1 + getLevel(parent.from, visited);
            }}
            
            nodes.forEach(function(node) {{
                var level = getLevel(node.id, new Set());
                if (!levelMap[level]) levelMap[level] = [];
                levelMap[level].push(node.id);
            }});
            
            Object.keys(levelMap).forEach(function(level) {{
                var count = levelMap[level].length;
                levelMap[level].forEach(function(nodeId, i) {{
                    positions[nodeId] = {{
                        x: 100 + parseInt(level) * 150,
                        y: 100 + (i - (count-1)/2) * 80
                    }};
                }});
            }});
            
            ctx.strokeStyle = '#555';
            ctx.lineWidth = 2;
            edges.forEach(function(edge) {{
                var from = positions[edge.from];
                var to = positions[edge.to];
                if (from && to) {{
                    ctx.beginPath();
                    ctx.moveTo(from.x, from.y);
                    ctx.lineTo(to.x, to.y);
                    ctx.stroke();
                }}
            }});
            
            nodes.forEach(function(node) {{
                var pos = positions[node.id];
                if (!pos) return;
                
                ctx.fillStyle = node.color;
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, node.size, 0, 2 * Math.PI);
                ctx.fill();
                
                ctx.fillStyle = '#fff';
                ctx.font = '10px Arial';
                ctx.textAlign = 'center';
                var lines = node.label.split('\\n');
                lines.forEach(function(line, i) {{
                    ctx.fillText(line, pos.x, pos.y + node.size + 12 + i * 12);
                }});
            }});
        }}
        
        drawNetwork();
    </script>
    
    <p style="color:#666; margin-top:20px;">Generated: {datetime.now(timezone.utc).isoformat()}</p>
</body>
</html>"""
        
        if output_path:
            output_path.write_text(html, encoding="utf-8")
        else:
            default_path = VISUALIZATION_DIR / f"lineage_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
            default_path.write_text(html, encoding="utf-8")
        
        return html
    
    def generate_progress_chart(self) -> str:
        archive_file = LEARNING_DIR / "improvement_archive.json"
        if not archive_file.exists():
            return "No improvement archive found."
        
        try:
            archive = json.loads(archive_file.read_text(encoding="utf-8"))
        except:
            return "Failed to load improvement archive."
        
        improvements = archive.get("improvements", [])
        generations = archive.get("generations", [])
        
        lines = [
            "IMPROVEMENT PROGRESS",
            "=" * 50,
            "",
        ]
        
        if not improvements:
            lines.append("No improvements recorded yet.")
            return "\n".join(lines)
        
        lines.append(f"Total Improvements: {len(improvements)}")
        lines.append(f"Total Generations: {len(generations)}")
        lines.append(f"Total Accuracy Gain: {archive.get('total_accuracy_gain', 0):.3f}")
        lines.append("")
        
        lines.append("ACCURACY OVER TIME:")
        
        best_scores = []
        current_best = 0.0
        
        for imp in improvements:
            delta = imp.get("accuracy_delta", 0)
            if delta > 0:
                current_best += delta
            best_scores.append(current_best)
        
        max_score = max(best_scores) if best_scores else 1.0
        chart_width = 40
        
        for i, score in enumerate(best_scores[-20:]):
            bar_len = int((score / max(max_score, 0.001)) * chart_width)
            bar = "█" * bar_len + "░" * (chart_width - bar_len)
            lines.append(f"  {i+1:3d} │{bar}│ {score:.3f}")
        
        lines.extend([
            "",
            "█ = Cumulative accuracy gain",
            "",
        ])
        
        return "\n".join(lines)


def generate_all_visualizations() -> dict[str, Any]:
    visualizer = LineageVisualizer()
    
    results: dict[str, Any] = {
        "ascii_tree": visualizer.generate_ascii_tree(),
        "progress_chart": visualizer.generate_progress_chart(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_count": len(visualizer.lineage.get_all_nodes()),
        "best_score": visualizer.lineage.get_best_score(),
    }
    
    html_file = VISUALIZATION_DIR / f"lineage_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    visualizer.generate_html_tree(html_file)
    results["html_file"] = str(html_file)
    
    return results


def print_lineage_tree() -> str:
    visualizer = LineageVisualizer()
    return visualizer.generate_ascii_tree()


def print_progress_chart() -> str:
    visualizer = LineageVisualizer()
    return visualizer.generate_progress_chart()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Agent BLACK Visualization")
    parser.add_argument("--tree", action="store_true", help="Show ASCII tree")
    parser.add_argument("--progress", action="store_true", help="Show progress chart")
    parser.add_argument("--html", action="store_true", help="Generate HTML visualization")
    parser.add_argument("--all", action="store_true", help="Generate all visualizations")
    args = parser.parse_args()
    
    visualizer = LineageVisualizer()
    
    if args.tree:
        print(visualizer.generate_ascii_tree())
    elif args.progress:
        print(visualizer.generate_progress_chart())
    elif args.html:
        html_file = VISUALIZATION_DIR / "lineage.html"
        visualizer.generate_html_tree(html_file)
        print(f"Generated: {html_file}")
    elif args.all:
        results = generate_all_visualizations()
        print(results["ascii_tree"])
        print(results["progress_chart"])
        print(f"\nHTML: {results['html_file']}")
    else:
        print(visualizer.generate_ascii_tree())
