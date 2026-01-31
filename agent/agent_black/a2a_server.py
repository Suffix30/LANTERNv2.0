"""
Agent BLACK A2A (Agent-to-Agent) Server
Requires: pip install fastapi uvicorn pydantic
"""

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None
    BaseModel = object

from typing import Optional, List
from pathlib import Path

if FASTAPI_AVAILABLE:
    from agent_black.lantern_runner import run_lantern
    from agent_black.model_registry import discover_models, select_model
    from agent_black.policies import validate_request
    from agent_black.knowledge_loader import load_knowledge

    app = FastAPI(title="Agent BLACK A2A Server")

    class A2AMessage(BaseModel):
        message: str
        attachments: Optional[List[str]] = []
        context_id: Optional[str] = None

    class A2AResponse(BaseModel):
        response: str
        context_id: Optional[str] = None

    _contexts = {}
    _models_dir = Path(__file__).parent / "models"

    @app.post("/a2a", response_model=A2AResponse)
    async def a2a_chat(request: A2AMessage):
        context_id = request.context_id or "default"
        
        if context_id not in _contexts:
            _contexts[context_id] = {
                "history": [],
                "knowledge": load_knowledge()
            }
        
        context = _contexts[context_id]
        
        if not validate_request(request.message):
            return A2AResponse(
                response="Request rejected by policy. Provide an authorized testing scope.",
                context_id=context_id
            )
        
        models = discover_models(_models_dir)
        selected = select_model(models, None)
        
        if not selected:
            return A2AResponse(
                response="No local model available. Please configure a model.",
                context_id=context_id
            )
        
        system_prompt = f"""You are Agent BLACK, a dedicated AI companion for LANTERN security testing.

    {context['knowledge'].get('agent_brain', '')}
    {context['knowledge'].get('operating_rules', '')}

    Your task: Translate the user's request into a LANTERN command and execute it.
    Always show the planned command before running it.
    """
        
        user_message = request.message
        context['history'].append({"role": "user", "content": user_message})
        
        planned_cmd = await plan_lantern_command(user_message, context['knowledge'])
        
        response_text = f"Planned LANTERN command:\n{' '.join(planned_cmd)}\n\n"
        
        if planned_cmd:
            response_text += "Executing LANTERN scan...\n"
            result = run_lantern(planned_cmd)
            response_text += f"Scan completed with exit code: {result}\n"
        else:
            response_text += "Could not generate valid LANTERN command. Please clarify your request."
        
        context['history'].append({"role": "assistant", "content": response_text})
        
        return A2AResponse(
            response=response_text,
            context_id=context_id
        )

    async def plan_lantern_command(user_message: str, knowledge: dict) -> List[str]:
        modules = knowledge.get('modules', {})
        presets = knowledge.get('presets', {})
        
        cmd = ["lantern"]
        
        if "fast" in user_message.lower():
            cmd.extend(["--fast"])
        elif "thorough" in user_message.lower() or "deep" in user_message.lower():
            cmd.extend(["--deep"])
        
        if "target" in user_message.lower() or "scan" in user_message.lower():
            target = extract_target(user_message)
            if target:
                cmd.extend(["-t", target])
        
        return cmd

    def extract_target(message: str) -> Optional[str]:
        import re
        url_pattern = r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'
        matches = re.findall(url_pattern, message)
        return matches[0] if matches else None

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "agent-black-a2a"}

if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        print("[!] FastAPI not installed. Run: pip install fastapi uvicorn")
        exit(1)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
