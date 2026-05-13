from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .scanner import PromptScanner

app = FastAPI(title="SafePrompt Gateway")
scanner = PromptScanner()

class PromptRequest(BaseModel):
    user_input: str

@app.get("/")
def read_root():
    return {"status": "SafePrompt Online"}

@app.post("/verify")
async def verify_prompt(request: PromptRequest):
    result = scanner.scan(request.user_input)
    
    if not result["is_safe"]:
        # Block the request
        raise HTTPException(status_code=403, detail=result["reason"])
    
    return {"status": "success", "message": "Prompt is safe to send to LLM."}