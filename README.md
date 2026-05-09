# CodeGuardian

CodeGuardian is an AI-powered code security review tool designed to help developers detect security vulnerabilities and code quality issues in Python code.

## Features

- **Security Vulnerability Detection**: Detect dangerous function usage like eval(), exec() to prevent code injection attacks
- **PEP8 Code Style Check**: Automatically check code formatting against Python coding standards
- **Performance Optimization Suggestions**: Analyze code for performance bottlenecks and provide optimization recommendations
- **RESTful API Service**: Built with FastAPI for easy integration into CI/CD pipelines

## Technology Stack

- Python 3.10+
- FastAPI
- OpenClaw for code analysis
- Planned integration with Xiaomi MiMo API for enhanced AI review capabilities

## Getting Started

```bash
pip install -r requirements.txt
python main.py
```

## Usage

```python
from codeguardian import CodeGuardian

guardian = CodeGuardian()
result = guardian.analyze("path/to/code.py")
print(result)
```

## License

MIT
