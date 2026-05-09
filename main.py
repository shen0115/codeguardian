from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import ast
import re

app = FastAPI(title="CodeGuardian API", version="1.0.0")

class CodeAnalysisRequest(BaseModel):
    code: str
    filename: str = "main.py"

class SecurityIssue(BaseModel):
    type: str
    message: str
    line: int
    column: int

class AnalysisResult(BaseModel):
    security_issues: list[SecurityIssue]
    pep8_issues: list[str]
    performance_suggestions: list[str]
    total_issues: int

DANGEROUS_FUNCTIONS = ['eval', 'exec', 'compile', 'input', 'open', 'os.system', 'subprocess.call']

def analyze_security(code: str) -> list[SecurityIssue]:
    issues = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in DANGEROUS_FUNCTIONS:
                        issues.append(SecurityIssue(
                            type="Security Risk",
                            message=f"Potentially dangerous function '{func_name}' used",
                            line=node.lineno,
                            column=node.col_offset
                        ))
                elif isinstance(node.func, ast.Attribute):
                    full_name = f"{node.func.value.id}.{node.func.attr}"
                    if full_name in DANGEROUS_FUNCTIONS:
                        issues.append(SecurityIssue(
                            type="Security Risk",
                            message=f"Potentially dangerous function '{full_name}' used",
                            line=node.lineno,
                            column=node.col_offset
                        ))
            if isinstance(node, ast.ImportFrom) and node.module == 'os':
                issues.append(SecurityIssue(
                    type="Security Warning",
                    message="Direct import of 'os' module may pose security risks",
                    line=node.lineno,
                    column=node.col_offset
                ))
    except SyntaxError as e:
        issues.append(SecurityIssue(
            type="Syntax Error",
            message=str(e),
            line=e.lineno or 0,
            column=e.offset or 0
        ))
    return issues

def analyze_pep8(code: str) -> list[str]:
    issues = []
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        if len(line) > 79:
            issues.append(f"Line {i}: Line too long ({len(line)} characters)")
        if line.rstrip().endswith('  '):
            issues.append(f"Line {i}: Trailing whitespace")
        if ' = ' not in line and '=' in line:
            if not re.match(r'^\s*class\s+|^\s*def\s+', line):
                if '==' not in line and '!=' not in line:
                    issues.append(f"Line {i}: Missing spaces around '=' operator")
    return issues

def analyze_performance(code: str) -> list[str]:
    suggestions = []
    if 'list.append' in code and 'for' in code:
        suggestions.append("Consider using list comprehensions instead of append() in loops")
    if 'dict.keys()' in code:
        suggestions.append("Consider using 'in dict' directly instead of 'in dict.keys()'")
    return suggestions

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_code(request: CodeAnalysisRequest):
    security_issues = analyze_security(request.code)
    pep8_issues = analyze_pep8(request.code)
    performance_suggestions = analyze_performance(request.code)
    
    return AnalysisResult(
        security_issues=security_issues,
        pep8_issues=pep8_issues,
        performance_suggestions=performance_suggestions,
        total_issues=len(security_issues) + len(pep8_issues)
    )

@app.get("/")
async def root():
    return {"message": "CodeGuardian API - AI-powered code security review tool"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
