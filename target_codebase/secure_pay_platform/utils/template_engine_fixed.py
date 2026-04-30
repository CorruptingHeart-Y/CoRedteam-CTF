"""
Template Engine - SECURED VERSION
Uses Jinja2 SandboxedEnvironment to prevent SSTI
"""

from jinja2 import Environment, FileSystemLoader, select_autoescape, SandboxedEnvironment
from jinja2.sandbox import ImmutableSandboxedEnvironment, SandboxedEnvironment as BaseSandbox
from typing import Any, Dict


class SecureTemplateEngine:
    """Secure template engine using Jinja2 sandbox"""
    
    def __init__(self):
        self.env = ImmutableSandboxedEnvironment(
            autoescape=select_autoescape(["html", "xml"]),
            undefined=jinja2.StrictUndefined
        )
    
    def render_safe(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render a pre-defined template file safely"""
        loader = FileSystemLoader("./templates")
        env = Environment(
            loader=loader,
            autoescape=select_autoescape(["html", "xml"])
        )
        
        template = env.get_template(template_name)
        return template.render(**context)


def render_user_template_safe(template_string: str, context: Dict[str, Any] = None) -> str:
    """
    Render user-provided template string - SECURE with Sandbox
    
    Uses Jinja2's SandboxedEnvironment which blocks access to dangerous attributes.
    """
    import jinja2
    
    if context is None:
        context = {}
    
    MAX_TEMPLATE_LENGTH = 5000
    if len(template_string) > MAX_TEMPLATE_LENGTH:
        raise ValueError(f"Template too large (max {MAX_TEMPLATE_LENGTH} characters)")
    
    env = SandboxedEnvironment(
        autoescape=True,
        undefined=jinja2.StrictUndefined
    )
    
    try:
        template = env.from_string(template_string)
        rendered_output = template.render(**context)
        return rendered_output
    except jinja2.SecurityError as e:
        return f"[Security Error] Template blocked: {e}"
    except Exception as e:
        return f"[Error] Template rendering failed: {e}"


def render_email_template_secure(user_input: str, variables: Dict[str, str] = None) -> str:
    """Render email notification with proper escaping"""
    if variables is None:
        variables = {}
    
    import html as html_module
    
    safe_input = html_module.escape(user_input)
    
    env = Environment(autoescape=True)
    
    template_str = f"""
    <html>
    <body>
        <h1>SecurePay Notification</h1>
        <div class="user-content">
            {{{{ user_content }}}}
        </div>
        % for key, value in variables.items() %}
        <p><strong>{{{{ key }}}}:</strong> {{{{ value }}}}</p>
        % endfor
    </body>
    </html>
    """
    
    template = env.from_string(template_str)
    return template.render(user_content=safe_input, **variables)


def generate_report_secure(data: Dict[str, Any], user_format: str) -> str:
    """Generate custom report format with security restrictions"""
    
    import jinja2
    
    if len(user_format) > 10000:
        return "Error: Template too large"
    
    BLOCKED_KEYWORDS = [
        "__class__", "__mro__", "__subclasses__",
        "__builtins__", "__import__", "config",
        "os.", "subprocess", "popen", "eval(",
        "exec(", "compile(", "open("
    ]
    
    format_lower = user_format.lower()
    for keyword in BLOCKED_KEYWORDS:
        if keyword in format_lower:
            return f"Error: Template contains blocked keyword '{keyword}'"
    
    env = SandboxedEnvironment(
        autoescape=True,
        undefined=jinja2.StrictUndefined
    )
    
    try:
        template = env.from_string(user_format)
        result = template.render(data=data)
        return result
    except jinja2.SecurityError as e:
        return f"Security Error: {e}"
    except Exception as e:
        return f"Template Error: {e}"


class SafeTemplateEngineFixed:
    """Truly secure template engine with comprehensive protection"""
    
    BLOCKED_PATTERNS = [
        r"\{\{.*__.*\}\}",
        r"\{%\s*import\s+.*%\}",
        r"\{%\s*include\s+.*%\}",
        r"\{%\s*extends\s+.*%\}",
        r".*config.*",
        r".*self.*",
        r".*request.*",
        r".*session.*",
    ]
    
    def __init__(self):
        self._sandbox = SandboxedEnvironment(
            autoescape=True,
            undefined=jinja2.StrictUndefined
        )
    
    def is_safe(self, template_string: str) -> tuple[bool, str]:
        """Check if template contains dangerous patterns"""
        import re
        
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, template_string, re.IGNORECASE | re.DOTALL):
                return False, f"Pattern matched: {pattern}"
        
        return True, ""
    
    def render(self, template_string: str, context: Dict[str, Any] = None) -> str:
        """Render template with full sandboxing"""
        is_safe, reason = self.is_safe(template_string)
        
        if not is_safe:
            return f"[BLOCKED] {reason}"
        
        try:
            template = self._sandbox.from_string(template_string)
            return template.render(**(context or {}))
        except Exception as e:
            return f"[ERROR] Template execution failed: {e}"


import jinja2
