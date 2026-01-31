"""
Agent BLACK Training Server
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

from typing import List, Optional, Dict
import json
from pathlib import Path

if FASTAPI_AVAILABLE:
    app = FastAPI(title="Agent BLACK Training Server")

    class TrainingExample(BaseModel):
        user_request: str
        expected_lantern_command: List[str]
        explanation: str
        context: Optional[Dict] = None

    class TrainingSession(BaseModel):
        teacher_model: str
        student_model: str = "agent_black"
        examples: List[TrainingExample]
        learning_objective: str

    class TrainingResponse(BaseModel):
        success: bool
        examples_added: int
        knowledge_updated: bool
        message: str

    _knowledge_path = Path(__file__).parent / "knowledge"
    _training_data_path = _knowledge_path / "training_examples.json"

    @app.post("/train", response_model=TrainingResponse)
    async def train_agent(training: TrainingSession):
        if not _training_data_path.exists():
            training_data = {"examples": []}
        else:
            with open(_training_data_path, 'r') as f:
                training_data = json.load(f)
        
        new_examples = []
        for example in training.examples:
            training_data["examples"].append({
                "user_request": example.user_request,
                "expected_command": example.expected_lantern_command,
                "explanation": example.explanation,
                "context": example.context or {},
                "taught_by": training.teacher_model,
                "objective": training.learning_objective
            })
            new_examples.append(example)
        
        with open(_training_data_path, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        return TrainingResponse(
            success=True,
            examples_added=len(new_examples),
            knowledge_updated=True,
            message=f"Added {len(new_examples)} training examples from {training.teacher_model}"
        )

    @app.get("/training/examples")
    async def get_training_examples():
        if not _training_data_path.exists():
            return {"examples": []}
        
        with open(_training_data_path, 'r') as f:
            return json.load(f)

    @app.post("/train/from-external")
    async def train_from_external(conversation: Dict):
        teacher_response = conversation.get("teacher_response", "")
        user_request = conversation.get("user_request", "")
        lantern_command = conversation.get("lantern_command", [])
        teacher_name = conversation.get("teacher_name", "external_ai")
        
        example = TrainingExample(
            user_request=user_request,
            expected_lantern_command=lantern_command,
            explanation=teacher_response
        )
        
        training = TrainingSession(
            teacher_model=teacher_name,
            examples=[example],
            learning_objective="Learn LANTERN command generation from external source"
        )
        
        return await train_agent(training)

if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        print("[!] FastAPI not installed. Run: pip install fastapi uvicorn")
        exit(1)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
