import os
import json
import uuid
import time
import tempfile
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from agentbreak.parsers import schema_parser, langgraph_parser
from agentbreak.scanner import path_finder, payload_generator, executor

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("AgentBreak API v0.3.0 ready")
    yield

app = FastAPI(title="AgentBreak API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.3.0"}

def _run_pipeline(graph, options_dict):
    max_depth = options_dict.get("max_depth", 8)
    external_only = options_dict.get("external_only", False)
    live = options_dict.get("live", False)
    
    paths = path_finder.find_attack_paths(graph, max_depth=max_depth, external_only=external_only)
    armed_paths = payload_generator.generate_all_payloads(paths)
    
    if live:
        results = executor.run(graph, armed_paths, mode="live", backend="groq")
        if options_dict.get("judge", False):
            from agentbreak.scanner.judge import judge_exploit
            for i in range(len(results)):
                results[i] = judge_exploit(results[i], backend="groq")
    else:
        results = executor.run(graph, armed_paths, mode="mock")
        
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest_severity_val = 0
    highest_severity_name = "INFO"
    should_fail = False
    
    fail_threshold = 3 # High
    
    for r in results:
        sev_val = severity_order.get(r.severity.name.lower(), 0)
        if r.exploited:
            if sev_val > highest_severity_val:
                highest_severity_val = sev_val
                highest_severity_name = r.severity.name
            if sev_val >= fail_threshold:
                should_fail = True
                
    exit_code = 1 if should_fail else 0
    
    return {
        "scan_id": str(uuid.uuid4()),
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "graph_summary": graph.summary(),
        "paths_found": len(paths),
        "results": [r.to_dict() for r in results],
        "highest_severity": highest_severity_name,
        "exit_code": exit_code
    }


@app.post("/scan")
async def scan(schema: UploadFile = File(...), options: Optional[str] = Form(None)):
    opts = {}
    if options:
        try:
            opts = json.loads(options)
        except json.JSONDecodeError:
            raise HTTPException(status_code=422, detail="options must be valid JSON")
            
    content = await schema.read()
    
    tmp = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False)
    tmp_path = tmp.name
    try:
        tmp.write(content)
        tmp.close()
        
        try:
            graph = schema_parser.parse(tmp_path)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid YAML schema: {e}")
            
        return _run_pipeline(graph, opts)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.post("/scan/langgraph")
async def scan_langgraph(agent_file: UploadFile = File(...), options: Optional[str] = Form(None)):
    opts = {}
    if options:
        try:
            opts = json.loads(options)
        except json.JSONDecodeError:
            raise HTTPException(status_code=422, detail="options must be valid JSON")
            
    content = await agent_file.read()
    
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
    tmp_path = tmp.name
    try:
        tmp.write(content)
        tmp.close()
        
        try:
            graph = langgraph_parser.parse(tmp_path)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid LangGraph schema: {e}")
            
        return _run_pipeline(graph, opts)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
