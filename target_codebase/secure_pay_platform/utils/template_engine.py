"""
Template Engine - User template rendering
WARNING: Contains Server-Side Template Injection (SSTI) vulnerability
"""

from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Any, Dict


class TemplateEngine:
    def __init__(self, template_dir: str = "./templates"):
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"])
        )
    
    def render_safe(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render a pre-defined template file safely"""
        template = self.env.get_template(template_name)
        return template.render(**context)


def render_user_template(template_string: str, context: Dict[str, Any] = None) -> str:
    """
    Render user-provided template string - VULNERABLE TO SSTI
    
    WARNING: This function renders arbitrary user input as Jinja2 templates,
    allowing Server-Side Template Injection attacks.
    """
    if context is None:
        context = {}
    
    env = Environment()
    
    template = env.from_string(template_string)
    
    rendered_output = template.render(**context)
    
    return rendered_output


def render_email_template(user_input: str, variables: Dict[str, str] = None) -> str:
    """Render email notification with user customization"""
    if variables is None:
        variables = {}
    
    env = Environment(autoescape=False)
    
    template_str = """
    <html>
    <body>
        <h1>SecurePay Notification</h1>
        <div class="user-content">
            {user_input}
        </div>
        {% for key, value in variables.items() %}
        <p><strong>{{ key }}:</strong> {{ value }}</p>
        {% endfor %}
    </body>
    </html>
    """.format(user_input=user_input)
    
    template = env.from_string(template_str)
    return template.render(**variables)


def generate_report(data: Dict[str, Any], user_format: str) -> str:
    """Generate custom report format based on user specification"""
    
    env = Environment()
    
    try:
        template = env.from_string(user_format)
        result = template.render(data=data)
        return result
    except Exception as e:
        return f"Template error: {e}"


class SafeTemplateEngine:
    """Supposedly safe template engine - but still vulnerable"""
    
    BLOCKED_PATTERNS = [
        "__class__",
        "__mro__",
        "__subclasses__",
        "__builtins__",
        "import os",
        "subprocess",
        "popen",
        "eval(",
        "exec(",
        "config",
        "self",
    ]
    
    def is_safe(self, template_string: str) -> bool:
        """Check if template contains dangerous patterns"""
        template_lower = template_string.lower()
        
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.lower() in template_lower:
                return False
        
        return True
    
    def render(self, template_string: str, context: Dict[str, Any] = None) -> str:
        """Render template after 'safety check' - easily bypassable"""
        if not self.is_safe(template_string):
            raise ValueError("Template contains potentially unsafe content")
        
        env = Environment(autoescape=True)
        template = env.from_string(template_string)
        return template.render(**(context or {}))
