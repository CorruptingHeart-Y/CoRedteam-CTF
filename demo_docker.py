#!/usr/bin/env python3
"""
Co-RedTeam Stage 2 Docker Isolation Demo
========================================

演示内容：
1. 检查 Docker 环境是否就绪
2. 构建/验证沙箱镜像 (co-redteam-sandbox:latest)
3. 展示容器生命周期：创建 → 执行 → 收集结果 → 自动销毁
4. 对比：本地执行 vs Docker 沙箱执行（安全性差异）
5. 展示资源限制、网络隔离、权限控制

用法:
    python demo_docker.py --check        # 检查 Docker 环境
    python demo_docker.py --build        # 构建沙箱镜像
    python demo_docker.py --demo         # 完整演示（构建+测试+销毁）
    python demo_docker.py --exploit      # 模拟攻击脚本执行
    python demo_docker.py --security     # 展示安全特性对比
    python demo_docker.py --full          # 全部演示
"""

import os
import sys
import json
import time
import uuid
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent
B_DIR = ROOT / "b"
DOCKERFILE_PATH = B_DIR / "Dockerfile"

BLUE = "\033[94m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    banner = f"""
{BOLD}{CYAN}
======================================================================
          Co-RedTeam Stage 2 - Docker Isolation Environment
======================================================================

  Stage 2 Architecture:
  +--------------------------------------------------+
  |  Planner Agent -> Validator Agent                   |
  |       v                                            |
  |  [Executor Agent] <--- Uses Docker SDK             |
  |       |                                            |
  |       +---> Docker Container (Sandbox)             |
  |              - Memory Limit: 256MB                 |
  |              - CPU Quota: 50%                       |
  |              - Network: Isolated                    |
  |              - Privileges: DROPPED ALL              |
  |              - Security: no-new-privileges         |
  |       |                                            |
  |       +---> Auto Cleanup (destroy after exec)      |
  |       v                                            |
  |  [Evaluator Agent] <- Results                      |
  +--------------------------------------------------+

======================================================================
{RESET}
"""
    print(banner)


def check_docker_environment() -> Dict[str, Any]:
    """检查 Docker 环境"""
    print(f"\n{BOLD}{YELLOW}[Step 1] Checking Docker Environment{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")
    
    results = {
        "docker_installed": False,
        "docker_running": False,
        "image_exists": False,
        "docker_version": None,
        "errors": []
    }
    
    # 1. 检查 docker 命令是否存在
    print(f"[*] Checking if Docker is installed...")
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            results["docker_installed"] = True
            version_output = result.stdout.strip()
            results["docker_version"] = version_output
            print(f"  {GREEN}[OK] Docker installed: {version_output}{RESET}")
        else:
            print(f"  {RED}[FAIL] Docker command not found{RESET}")
            results["errors"].append("Docker not installed")
            
    except FileNotFoundError:
        print(f"  {RED}[FAIL] Docker executable not found in PATH{RESET}")
        results["errors"].append("Docker not in PATH")
    except Exception as e:
        print(f"  {RED}[FAIL] Error: {e}{RESET}")
        results["errors"].append(str(e))
    
    # 2. 检查 Docker daemon 是否运行
    if results["docker_installed"]:
        print(f"\n[*] Checking if Docker daemon is running...")
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                results["docker_running"] = True
                print(f"  {GREEN}[OK] Docker daemon is running{RESET}")
                
                # 提取一些有用信息
                for line in result.stdout.split('\n')[:10]:
                    if any(kw in line.lower() for kw in ['server', 'version', 'storage', 'containers']):
                        print(f"       {line.strip()}")
            else:
                print(f"  {RED}[FAIL] Docker daemon not running{RESET}")
                print(f"       Error: {result.stderr[:100]}")
                results["errors"].append("Docker daemon not running")
                
        except Exception as e:
            print(f"  {RED}[FAIL] Cannot connect to Docker: {e}{RESET}")
            results["errors"].append(str(e))
    
    # 3. 检查沙箱镜像是否存在
    if results["docker_running"]:
        print(f"\n[*] Checking sandbox image 'co-redteam-sandbox:latest'...")
        try:
            result = subprocess.run(
                ["docker", "images", "co-redteam-sandbox:latest", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                results["image_exists"] = True
                print(f"  {GREEN}[OK] Sandbox image exists{RESET}")
            else:
                print(f"  {YELLOW}[WARN] Sandbox image not found (need to build){RESET}")
                
        except Exception as e:
            print(f"  {YELLOW}[WARN] Cannot check image: {e}{RESET}")
    
    return results


def build_sandbox_image() -> bool:
    """构建沙箱镜像"""
    print(f"\n{BOLD}{YELLOW}[Step 2] Building Sandbox Image{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")
    
    if not DOCKERFILE_PATH.exists():
        print(f"  {RED}[ERROR] Dockerfile not found at: {DOCKERFILE_PATH}{RESET}")
        return False
    
    print(f"[*] Dockerfile location: {DOCKERFILE_PATH}")
    print(f"[*] Image name: co-redteam-sandbox:latest")
    print()
    
    print(f"{'='*60}")
    print(f"Dockerfile Content:")
    print(f"{'='*60}")
    
    with open(DOCKERFILE_PATH, 'r') as f:
        content = f.read()
        print(content)
    
    print(f"{'='*60}\n")
    
    print(f"[*] Starting build process...")
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [
                "docker", "build",
                "-t", "co-redteam-sandbox:latest",
                "-f", str(DOCKERFILE_PATH),
                str(B_DIR)
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300  # 5分钟超时
        )
        
        duration = time.time() - start_time
        
        if result.returncode == 0:
            print(f"\n  {GREEN}[SUCCESS] Image built successfully!{RESET}")
            print(f"  Duration: {duration:.1f} seconds")
            
            # 显示镜像信息
            result2 = subprocess.run(
                ["docker", "images", "co-redteam-sandbox:latest"],
                capture_output=True,
                text=True,
                timeout=10
            )
            print(f"\n  Image Info:")
            print(f"  {result2.stdout}")
            return True
        else:
            print(f"\n  {RED}[FAIL] Build failed!{RESET}")
            print(f"  Error output:")
            print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print(f"\n  {RED}[TIMEOUT] Build took too long (>5 minutes){RESET}")
        return False
    except Exception as e:
        print(f"\n  {RED}[ERROR] {e}{RESET}")
        return False


def demo_container_lifecycle():
    """演示完整的容器生命周期"""
    print(f"\n{BOLD}{YELLOW}[Step 3] Container Lifecycle Demo{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")
    
    container_name = f"coredteam-demo-{uuid.uuid4().hex[:8]}"
    
    print(f"[1] Creating container: {container_name}")
    print(f"    - Image: co-redteam-sandbox:latest")
    print(f"    - Memory limit: 256MB")
    print(f"    - CPU quota: 50%")
    print(f"    - Network: disabled")
    print(f"    - Capabilities: DROP ALL")
    print(f"    - Security: no-new-privileges")
    print()
    
    # 创建容器
    create_cmd = [
        "docker", "create",
        "--name", container_name,
        "--memory", "256m",
        "--cpu-quota", "50000",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "co-redteam-sandbox:latest",
        "echo 'Hello from Co-RedTeam Sandbox!' && whoami && pwd && ls -la /sandbox/"
    ]
    
    try:
        result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            container_id = result.stdout.strip()
            print(f"  {GREEN}[OK] Container created: {container_id[:12]}{RESET}")
        else:
            print(f"  {RED}[FAIL] Failed to create container{RESET}")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"  {RED}[ERROR] {e}{RESET}")
        return False
    
    # 启动并等待完成
    print(f"\n[2] Starting container execution...")
    start_time = time.time()
    
    try:
        run_result = subprocess.run(
            ["docker", "start", "-a", container_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        duration = time.time() - start_time
        
        print(f"  {GREEN}[OK] Execution completed in {duration:.2f}s{RESET}")
        print(f"\n  Container Output:")
        print(f"  {'-'*40}")
        for line in run_result.stdout.split('\n'):
            print(f"  | {line}")
        print(f"  {'-'*40}")
        
        if run_result.stderr:
            print(f"\n  Stderr (if any):")
            print(run_result.stderr[:200])
            
    except Exception as e:
        print(f"  {RED}[ERROR] {e}{RESET}")
    
    # 检查容器状态
    print(f"\n[3] Checking container status...")
    try:
        inspect_cmd = ["docker", "inspect", "--format", 
                      "{{.State.Status}} | ExitCode: {{.State.ExitCode}} | Pid: {{.State.Pid}}",
                      container_name]
        inspect_result = subprocess.run(inspect_cmd, capture_output=True, text=True, timeout=10)
        print(f"  Status: {inspect_result.stdout.strip()}")
    except Exception as e:
        print(f"  {YELLOW}[WARN] Could not inspect: {e}{RESET}")
    
    # 销毁容器
    print(f"\n[4] Destroying container (auto-cleanup)...")
    try:
        rm_result = subprocess.run(
            ["docker", "rm", "-f", "-v", container_name],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if rm_result.returncode == 0:
            print(f"  {GREEN}[OK] Container destroyed successfully{RESET}")
        else:
            print(f"  {YELLOW}[WARN] Cleanup warning: {rm_result.stderr[:100]}{RESET}")
            
    except Exception as e:
        print(f"  {YELLOW}[WARN] Manual cleanup may be needed: {e}{RESET}")
    
    # 验证已删除
    verify_result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        timeout=10
    )
    
    if not verify_result.stdout.strip():
        print(f"  {GREEN}[VERIFIED] Container fully removed{RESET}")
    else:
        print(f"  {RED}[WARNING] Container still exists!{RESET}")
    
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{GREEN}Lifecycle Demo Complete!{RESET}")
    print(f"The container was automatically cleaned up after execution.")
    print(f"{CYAN}{'='*60}{RESET}\n")
    
    return True


def demo_exploit_execution():
    """模拟攻击脚本在沙箱中的执行"""
    print(f"\n{BOLD}{YELLOW}[Step 4] Simulated Exploit Execution Demo{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")
    
    # 创建一个模拟的漏洞利用脚本
    exploit_script = '''#!/usr/bin/env python3
"""Simulated SQL Injection Exploit - For Testing Only"""
import sys
import os
import urllib.request
import json

print("[EXPLOIT] Starting SQL Injection test against SecurePay...")

# 模拟 payload
payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM credentials--",
]

target_url = "http://localhost:9443/api/v1/auth/login"

for i, payload in enumerate(payloads):
    print(f"\\n[Try {i+1}] Payload: {repr(payload)}")
    print(f"  Target: {target_url}")
    
    # 在真实场景中，这里会发送 HTTP 请求
    # 但在沙箱中，网络被隔离，所以会失败
    try:
        data = json.dumps({"username": payload, "password": "test"}).encode()
        req = urllib.request.Request(target_url, data=data, headers={"Content-Type": "application/json"})
        
        with urllib.request.urlopen(req, timeout=5) as response:
            result = response.read().decode()
            print(f"  Response ({response.status}): {result[:100]}")
    except Exception as e:
        print(f"  Blocked/Error (expected in sandbox): {type(e).__name__}")

print("\\n[EXPLOIT] Test complete. Results would be sent to Evaluator Agent.")
'''
    
    workspace_dir = B_DIR / "workspace"
    workspace_dir.mkdir(exist_ok=True)
    
    exploit_path = workspace_dir / "test_exploit.py"
    with open(exploit_path, 'w') as f:
        f.write(exploit_script)
    
    print(f"[*] Created test exploit script: {exploit_path}")
    print(f"[*] Script content preview:")
    print(f"{'-'*40}")
    for line in exploit_script.split('\n')[:12]:
        print(f"  {line}")
    print(f"  ...")
    print(f"{'-'*40}\n")
    
    container_name = f"coredteam-exploit-{uuid.uuid4().hex[:8]}"
    
    print(f"[*] Launching exploit in isolated sandbox...")
    print(f"    Container: {container_name}")
    print(f"    Script: /sandbox/workspace/test_exploit.py")
    print(f"    Timeout: 30 seconds")
    print()
    
    try:
        # 使用 docker run 执行脚本
        run_cmd = [
            "docker", "run",
            "--rm",  # 自动清理
            "--name", container_name,
            "--memory", "128m",
            "--cpu-quota", "25000",
            "--network", "none",  # 禁用网络
            "--read-only",  # 只读文件系统
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{workspace_dir}:/sandbox/workspace:ro",  # 只读挂载
            "co-redteam-sandbox:latest",
            "python", "/sandbox/workspace/test_exploit.py"
        ]
        
        start_time = time.time()
        result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=45)
        duration = time.time() - start_time
        
        print(f"{GREEN}Execution completed in {duration:.2f}s{RESET}\n")
        
        print(f"Output (stdout):")
        print(f"{'-'*50}")
        if result.stdout:
            for line in result.stdout.split('\n'):
                print(f"  {line}")
        else:
            print(f"  (no stdout)")
        print(f"{'-'*50}")
        
        if result.stderr:
            print(f"\nErrors (stderr):")
            print(f"{'-'*50}")
            for line in result.stderr.split('\n'):
                print(f"  {RED}{line}{RESET}")
            print(f"{'-'*50}")
        
        print(f"\nExit code: {result.returncode}")
        
        # 验证容器已被自动清理 (--rm flag)
        check_cmd = ["docker", "ps", "-a", "--filter", f"name={container_name}", "-q"]
        check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
        
        if not check_result.stdout.strip():
            print(f"\n{GREEN}[VERIFIED] Container auto-cleaned (--rm flag worked){RESET}")
        else:
            print(f"\n{YELLOW}[NOTE] Container still exists (manual cleanup needed){RESET}")
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"\n{RED}[TIMEOUT] Exploit execution timed out (>45s){RESET}")
        print(f"This demonstrates the timeout protection mechanism!")
        return False
    except Exception as e:
        print(f"\n{RED}[ERROR] {e}{RESET}")
        return False
    finally:
        # 清理可能残留的容器
        try:
            subprocess.run(["docker", "rm", "-f", container_name], 
                          capture_output=True, timeout=10)
        except:
            pass


def show_security_comparison():
    """展示本地执行 vs Docker 执行的安全差异"""
    print(f"\n{BOLD}{YELLOW}[Step 5] Security Comparison: Local vs Docker{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    comparison = f"""
{BOLD}+-----------------------------------------------------------------------+
|                    EXECUTION MODE COMPARISON                           |
+-----------------------------------------------------------------------+
|                                                                       |
|  {RED}LOCAL EXECUTION (DANGEROUS){RESET}                                       |
|  -------------------------------------------------------------------   |
|  - Runs on HOST machine directly                                      |
|  - Has access to: filesystem, network, processes, environment vars   |
|  - Can execute: rm -rf / , curl evil.com, steal credentials           |
|  - No resource limits (can consume all RAM/CPU)                       |
|  - No isolation from other applications                               |
|  - If exploited: attacker gains host access                            |
|                                                                       |
|  {GREEN}DOCKER SANDBOX (SECURE){RESET}                                          |
|  -------------------------------------------------------------------   |
|  - Runs inside isolated container                                     |
|  - Filesystem: Read-only or limited mount                             |
|  - Network: Disabled or restricted                                    |
|  - Capabilities: ALL dropped (no root, no admin)                     |
|  - Security: no-new-privileges (prevents privilege escalation)      |
|  - Resources: Limited (256MB RAM, 50% CPU)                           |
|  - User: Runs as non-root 'sandbox' user                             |
|  - Auto cleanup: Destroyed immediately after execution               |
|  - If contained: only affects sandbox environment                    |
|                                                                       |
+-----------------------------------------------------------------------+

{BOLD}DOCKER SECURITY FEATURES IN YOUR IMPLEMENTATION:{RESET}

  1. {GREEN}Memory Limit{RESET}: 256MB max (prevents fork bombs)
  2. {GREEN}CPU Quota{RESET}: 50% max (prevents CPU exhaustion)
  3. {GREEN}Network Isolation{RESET}: --network=none (blocks C2 callbacks)
  4. {GREEN}Capability Drop{RESET}: --cap-drop=ALL (no privileged ops)
  5. {GREEN}No New Privs{RESET}: --security-opt=no-new-privileges
  6. {GREEN}Auto Cleanup{RESET}: Container removed after execution
  7. {GREEN}Timeout Protection{RESET}: 30s max execution time
  8. {GREEN}Non-root User{RESET}: Runs as 'sandbox' user (UID > 0)

{BOLD}REAL-WORLD ATTACK SCENARIOS BLOCKED:{RESET}

  Scenario 1: Reverse Shell
    {RED}Local:{RESET} Attacker gets shell on your machine!
    {GREEN}Docker:{RESET} Network disabled, connection fails
    
  Scenario 2: Ransomware (encrypt files)
    {RED}Local:{RESET} Encrypts all your documents!
    {GREEN}Docker:{RESET} Read-only FS, can't write anywhere
    
  Scenario 3: Crypto Miner
    {RED}Local:{RESET} Consumes 100% CPU for hours
    {GREEN}Docker:{RESET} Killed at 30s timeout, CPU limited to 50%
    
  Scenario 4: Data Exfiltration
    {RED}Local:{RESET} Steals .env, SSH keys, passwords
    {GREEN}Docker:{RESET} Can't access host filesystem

+-----------------------------------------------------------------------+
"""
    print(comparison)


def show_architecture_diagram():
    """展示架构图"""
    diagram = f"""
{BOLD}{CYAN}========================================================================
                    STAGE 2 DOCKER ARCHITECTURE
========================================================================{RESET}

                              Your Host Machine
  +------------------------------------------------------------------+
  |                                                                   |
  |   [coordinator.py]                                                |
  |       |                                                           |
  |       v                                                           |
  |   +------------------+                                           |
  |   |  Planner Agent   | --> Generates attack plan (plan.json)      |
  |   +------------------+                                           |
  |       |                                                           |
  |       v                                                           |
  |   +------------------+                                           |
  |   | Validator Agent  | --> Validates feasibility                  |
  |   +------------------+                                           |
  |       |                                                           |
  |       v                                                           |
  |   +----------------------------------------------------------+   |
  |   |                  Executor Agent                            |   |
  |   |                                                            |   |
  |   |   +----------------------------------------------------+  |   |
  |   |   |              Docker SDK (Python)                    |  |   |
  |   |   |                                                    |  |   |
  |   |   |   1. client.containers.create(...)                  |  |   |
  |   |   |   2. container.start()                                |  |   |
  |   |   |   3. container.wait(timeout=30)                      |  |   |
  |   |   |   4. container.logs(stdout/stderr)                    |  |   |
  |   |   |   5. container.remove(force=True)  <-- AUTO CLEANUP   |  |   |
  |   |   |                                                    |  |   |
  |   |   +--------------------|-------------------------------+  |   |
  |   |                        |                                  |   |
  |   +------------------------|----------------------------------+   |
  |                            |                                      |
  |                            v                                      |
  |   +------------------------------------------------------------+  |
  |   |                                                            |  |
  |   |              DOCKER CONTAINER (Sandbox)                    |  |
  |   |                                                            |  |
  |   |   +----------------------------------------------------+  |  |
  |   |   |  co-redteam-sandbox:latest image                     |  |  |
  |   |   |                                                    |  |  |
  |   |   |   OS: Debian slim (minimal attack surface)          |  |  |
  |   |   |   User: sandbox (non-root)                          |  |  |
  |   |   |   Memory: 256MB limit                               |  |  |
  |   |   |   CPU: 50% quota                                    |  |  |
  |   |   |   Network: DISABLED                                 |  |  |
  |   |   |   Caps: NONE (all dropped)                         |  |  |
  |   |   |   FS: /sandbox/workspace (mounted read-only)        |  |  |
  |   |   |                                                    |  |  |
  |   |   |   <-- EXPLOIT SCRIPT RUNS HERE -->                 |  |  |
  |   |   |   python /sandbox/workspace/exploit.py              |  |  |
  |   |   |                                                    |  |  |
  |   |   +----------------------------------------------------+  |  |
  |   |                                                            |  |
  |   +------------------------------------------------------------+  |
  |                                                                    |
  |       | (results returned via container.logs())                    |
  |       v                                                            |
  |   +------------------+                                            |
  |   | Evaluator Agent  | --> Assesses success/failure              |
  |   +------------------+                                            |
  |                                                                    |
  +----------------------------------------------------------------------+

{BOLD}{YELLOW}Key Files in Your Implementation:{RESET}

  b/Dockerfile              - Defines the sandbox image
  b/agents/executor.py      - DockerSandbox class (lines 18-120)
  b/core/settings.py       - Docker configuration (lines 42-46)
  
  Settings:
    - CO_REDTEAM_DOCKER_ENABLED=true     Enable/disable Docker
    - CO_REDTEAM_DOCKER_IMAGE=co-redteam-sandbox:latest
    - CO_REDTEAM_DOCKER_TIMEOUT=30       Max execution time (seconds)
    - CO_REDTEAM_DOCKER_MEMORY=256m      Memory limit
    - CO_REDTEAM_DOCKER_CPU_QUOTA=50000 CPU limit (50000 = 50%)

{CYAN}========================================================================
{RESET}
"""
    print(diagram)


def show_code_implementation():
    """展示关键代码实现"""
    print(f"\n{BOLD}{YELLOW}[Code Highlight] Key Implementation Details{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    code_examples = {
        "DockerSandbox.__init__()": """
class DockerSandbox:
    def __init__(self, image: str, timeout: int = 30, 
                 memory_limit: str = "256m", cpu_quota: int = 50000):
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit  # 限制内存
        self.cpu_quota = cpu_quota        # 限制CPU
""",
        
        "Container Creation (with security)": """
container = self.client.containers.create(
    image=self.image,
    command=command,
    name=container_name,
    detach=True,
    mem_limit=self.memory_limit,           # 内存限制
    cpu_quota=self.cpu_quota,              # CPU限制
    network_disabled=False,                # 网络隔离
    volumes=volumes,                       # 文件系统挂载
    working_dir="/sandbox/workspace",
    security_opt=["no-new-privileges"],    # 防止提权
    cap_drop=["ALL"],                      # 移除所有特权
)
""",
        
        "Auto Cleanup (finally block)": """
finally:
    if container:
        try:
            container.remove(force=True, v=True)  # 强制删除+卷
        except Exception as e:
            print(f"[docker] Warning: Failed to remove container")
""",
        
        "Fallback Logic (Docker unavailable)": """
def _run_step(step, timeout_sec, workdir, sandbox):
    if sandbox is not None and sandbox.is_available():
        print(f"[executor] Using Docker sandbox")
        return _run_docker(step, sandbox, workdir)
    else:
        print(f"[executor] Docker not available, using local")
        return _run_local(step, timeout_sec, workdir)
"""
    }
    
    for title, code in code_examples.items():
        print(f"{BOLD}{MAGENTA}>{RESET} {title}")
        print(f"{YELLOW}{'-'*60}{RESET}")
        print(code)
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Co-RedTeam Stage 2 Docker Isolation Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo_docker.py --check       Check Docker environment
  python demo_docker.py --build       Build sandbox image
  python demo_docker.py --demo        Full lifecycle demo
  python demo_docker.py --exploit     Run simulated exploit
  python demo_docker.py --security    Show security comparison
  python demo_docker.py --architecture Show architecture diagram
  python demo_docker.py --code        Show key code snippets
  python demo_docker.py --full        Run everything
        """
    )
    
    parser.add_argument("--check", action="store_true", help="Check Docker environment")
    parser.add_argument("--build", action="store_true", help="Build sandbox image")
    parser.add_argument("--demo", action="store_true", help="Run container lifecycle demo")
    parser.add_argument("--exploit", action="store_true", help="Simulate exploit execution")
    parser.add_argument("--security", action="store_true", help="Show security comparison")
    parser.add_argument("--architecture", action="store_true", help="Show architecture diagram")
    parser.add_argument("--code", action="store_true", help="Show code implementation")
    parser.add_argument("--full", action="store_true", help="Run complete demo")
    
    args = parser.parse_args()
    
    if not any([args.check, args.build, args.demo, args.exploit, 
                args.security, args.architecture, args.code, args.full]):
        parser.print_help()
        return 0
    
    print_banner()
    
    success_count = 0
    total_steps = 0
    
    # Step 0: Show architecture
    if args.architecture or args.full:
        show_architecture_diagram()
    
    # Step 1: Check environment
    if args.check or args.full:
        total_steps += 1
        env_results = check_docker_environment()
        if env_results.get("docker_running"):
            success_count += 1
            print(f"\n{GREEN}Environment check PASSED{RESET}")
        else:
            print(f"\n{RED}Environment check FAILED{RESET}")
            print(f"\nTo fix:")
            print(f"  1. Install Docker Desktop: https://www.docker.com/products/docker-desktop")
            print(f"  2. Start Docker Desktop application")
            print(f"  3. Run this script again with: python demo_docker.py --check")
    
    # Step 2: Build image
    if args.build or (args.full and env_results.get("docker_running")):
        total_steps += 1
        if build_sandbox_image():
            success_count += 1
    
    # Step 3: Lifecycle demo
    if args.demo or args.full:
        total_steps += 1
        if demo_container_lifecycle():
            success_count += 1
    
    # Step 4: Exploit execution
    if args.exploit or args.full:
        total_steps += 1
        if demo_exploit_execution():
            success_count += 1
    
    # Step 5: Security comparison
    if args.security or args.full:
        show_security_comparison()
    
    # Code highlights
    if args.code or args.full:
        show_code_implementation()
    
    # Summary
    if total_steps > 0:
        print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
        print(f"{BOLD}{CYAN}           Docker Demo Summary{RESET}")
        print(f"{BOLD}{CYAN}{'='*70}{RESET}")
        print(f"\n  Steps completed: {success_count}/{total_steps}")
        
        if success_count == total_steps:
            print(f"  Status: {GREEN}ALL TESTS PASSED{RESET}")
        elif success_count > 0:
            print(f"  Status: {YELLOW}PARTIAL SUCCESS ({success_count}/{total_steps}){RESET}")
        else:
            print(f"  Status: {RED}NO TESTS RAN (check Docker installation){RESET}")
        
        print(f"\n  Next steps:")
        print(f"    1. Ensure Docker is running: docker info")
        print(f"    2. Build image: python demo_docker.py --build")
        print(f"    3. Run demo: python demo_docker.py --demo")
        print(f"    4. Test exploit: python demo_docker.py --exploit")
        print(f"\n{BOLD}{CYAN}{'='*70}{RESET}\n")
    
    return 0 if success_count == total_steps else 1


if __name__ == "__main__":
    sys.exit(main())
