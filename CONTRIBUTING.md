# Contributing to LANTERN

Thank you for your interest in contributing to LANTERN!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/LANTERNv2.0.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Install dependencies: `pip install -r requirements.txt`

## Development Guidelines

### Code Style
- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Keep functions focused and concise
- Maximum line length: 127 characters

### Module Development
When creating new scanner modules:

```python
from modules.base import BaseModule

class YourModule(BaseModule):
    name = "your_module"
    description = "What it scans for"
    
    async def run(self, target, options):
        # Implementation
        pass
```

### Testing
- Test your changes locally before submitting
- Ensure existing tests still pass
- Add tests for new functionality when applicable

## Submitting Changes

1. Commit your changes with clear messages
2. Push to your fork
3. Open a Pull Request against `main`
4. Fill out the PR template completely
5. Wait for review

## Reporting Issues

- Use the issue templates provided
- Include reproduction steps
- Provide environment details
- Include relevant error messages

## Security Vulnerabilities

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md) for details.

## Questions?

Open a discussion or issue if you have questions about contributing.
