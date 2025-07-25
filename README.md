# APIC-MCP-Server

A comprehensive Model Context Protocol (MCP) server for managing and analyzing Cisco ACI (Application Centric Infrastructure) fabrics. This tool provides a powerful interface for network administrators and developers to interact with Cisco APIC controllers, perform analysis, and generate detailed reports.

## 🚀 What is APIC-MCP-Server?

The APIC-MCP-Server is a Python-based MCP server and it provides:

- **🔌 Direct APIC Integration**: Seamless authentication and communication with Cisco APIC controllers
- **📊 Comprehensive Analysis**: Detailed tenant, EPG, BD, VRF, and security policy analysis
- **🔍 Security Monitoring**: Contract deny logging, vulnerability checking via PSIRT API
- **📋 Documentation Generation**: Automated Word document generation for infrastructure reports
- **⚡ Fabric Monitoring**: Live fabric health monitoring and troubleshooting capabilities

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │  APIC-MCP-Server │    │  Cisco APIC     │
│                 │    │                  │    │  Controllers    │
│ • VS Code       │◄──►│ • FastMCP        │◄──►│                 │
│ • Claude        │    │ • Authentication │    │ • REST API      │
│ • Custom Tools  │    │ • Analysis Tools │    │ • Policy Data   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  External APIs  │
                       │                 │
                       │ • Cisco PSIRT   │
                       │ • Field Notices │
                       │ • Vulnerability │
                       │   Database      │
                       └─────────────────┘
```

## 📦 Components

### Core Components

#### 1. **apic_mcp_server.py** (Main Server)
- **FastMCP Framework**: Primary MCP server implementation
- **20+ Tools**: Comprehensive set of APIC management tools
- **Document Generation**: Creates professional Word reports

#### 2. **auth_utils.py** (Authentication)
- **APIC Authentication**: Secure JWT token management
- **Session Management**: Persistent connection handling
- **Error Handling**: Robust authentication error recovery

### Configuration Files

#### 3. **.env.template** (Environment Template)
- **Environment Setup**: Template for environment variables
- **APIC Configuration**: Connection settings and credentials
- **Security**: PSIRT API configuration for vulnerability checking

#### 4. **.vscode/** (VS Code Integration)
- **MCP Configuration**: VS Code MCP server settings
- **Development Setup**: IDE configuration for development

```bash
# APIC Connection Settings
APIC_URL=https://your-apic.example.com
APIC_USERNAME=admin
APIC_PASSWORD=your-password
APIC_VERIFY_SSL=false

# PSIRT API Settings (Optional)
MY_PSIRT_API_URL=https://api.cisco.com/security/advisories
MY_PSIRT_CLIENT_ID=your-client-id
MY_PSIRT_CLIENT_SECRET=your-client-secret
```

## 🛠️ Available Tools

### Authentication & Status
- `authenticate_apic()` - Authenticate to APIC controller
- `get_apic_status()` - Check current session status
- `logout_apic()` - Logout and cleanup session

### Fabric Discovery
- `get_tenants()` - List all tenants
- `get_fabric_nodes()` - List fabric switches and controllers
- `search_objects_by_name()` - Search for specific objects

### Tenant Management
- `get_application_profiles()` - List application profiles
- `get_epgs()` - List endpoint groups
- `get_bridge_domains()` - List bridge domains
- `get_vrfs()` - List VRFs
- `get_contracts()` - List security contracts

### Security Analysis
- `get_denied_logs_for_tenant()` - Check audit violations
- `get_contract_denies_for_tenant()` - Analyze contract denies
- `get_contract_permit_logs_for_tenant()` - Review permitted traffic

### External Connectivity
- `fetch_apic_class()` - Generic APIC class queries
- `get_node_interface_status()` - Interface operational status

### Security Intelligence
- `verify_apic_vulnerability()` - Check APIC vulnerabilities
- `check_cisco_aci_switches_psirt()` - PSIRT advisory lookup
- `get_apic_field_notices()` - APIC field notices
- `get_nexus_9000_field_notices()` - Switch field notices

### Documentation
- `create_tenant_analysis_document()` - Generate Word reports

## 🚀 Getting Started

### Prerequisites
- Python 3.12+ for best compatibility
- Access to Cisco APIC controller
- Network connectivity to APIC management interface
- VS Code (for VS Code integration) or Claude Desktop (for Claude integration)

### Installation

1. **Clone the Repository**
```bash
git clone https://wwwin-github.cisco.com/bageze/APIC-MCP-Server.git
cd mcp-server
```

2. **Install Dependencies**

```bash
# Install all dependencies
pip install -r requirements.txt
```

The `requirements.txt` includes:

- fastmcp (core MCP server framework)
- requests (HTTP client)
- python-dotenv (environment variable management)
- beautifulsoup4 (HTML parsing)
- python-docx (Word document generation)
- uvicorn (optional, async server)
# pytest, flake8 (optional, for testing/linting)

3. **Configure Environment**
```bash
# Copy and edit environment file
cp .env.template .env
# Edit .env with your APIC and credentials
# PSIRT client id and client secret are optional but recommended for security analysis
```

Edit the `.env` file with your APIC details:
```bash
# APIC Connection Settings
APIC_URL=https://your-apic.example.com
APIC_USERNAME=admin
APIC_PASSWORD=your-password
APIC_VERIFY_SSL=false

# PSIRT API Settings (Optional)
MY_PSIRT_API_URL=https://api.cisco.com/security/advisories
MY_PSIRT_CLIENT_ID=your-client-id
MY_PSIRT_CLIENT_SECRET=your-client-secret
```

### 🔧 MCP Client Configuration

#### Option 1: VS Code Integration

1. **Install the MCP Extension**
   - Install the "Model Context Protocol" extension in VS Code
   - Or install "Claude Dev" extension which supports MCP

2. **Configure MCP Server**
   
   Create or update your VS Code `mcp.json`:
   ```json
   {
     "mcpServers": {
       "cisco-aci-apic": {
         "command": "/Users/bageze/.local/bin/uv",
         "args": [
           "run",
           "--with",
           "mcp",
           "mcp",
           "run",
           "/path/to/your/mcp-server/apic_mcp_server.py"
         ]
       }
     }
   }
   ```

   Or use the included `.vscode/mcp.json` configuration:
   ```json
   {
     "servers": {
       "cisco-aci-apic": {
         "command": "/Users/bageze/.local/bin/uv",
         "args": [
           "run",
           "--with",
           "mcp",
           "mcp",
           "run",
           "apic_mcp_server.py"
         ]
       }
     }
   }
   ```
   *Note: Environment variables can be set in `.env` file or added to the config above.*
  
   ```

3. **Restart VS Code** and the MCP server will be available in your VS Code environment.

#### Option 2: Claude Desktop Integration

1. **Locate or create Claude Desktop Config**
   ```bash
   # macOS
   ~/Library/Application Support/Claude/claude_desktop_config.json
   
   # Windows
   %APPDATA%\Claude\claude_desktop_config.json
   
   # Linux
   ~/.config/Claude/claude_desktop_config.json
   ```

2. **Add MCP Server Configuration**
   
   Edit `claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "cisco-aci-apic": {
         "command": "/Users/bageze/.local/bin/uv",
         "args": [
           "run",
           "--with",
           "mcp",
           "mcp",
           "run",
           "/full/path/to/your/mcp-server/apic_mcp_server.py"
         ]
       }
     }
   }
   ```

3. **Restart Claude Desktop** and the APIC tools will be available in your conversations.


### 🧪 Testing Your Setup

1. **Test Environment Variables**
```bash
# Verify your .env file is loaded correctly
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
print(f'APIC URL: {os.getenv(\"APIC_URL\")}')
print(f'Username: {os.getenv(\"APIC_USERNAME\")}')
"
```

2. **Test MCP Server**
```bash
# Basic import test
python -c "
from apic_mcp_server import mcp
print('✅ MCP Server loaded successfully')
"
```

3. **Test APIC Connectivity**
```bash
# Test network connectivity to your APIC
curl -k https://your-apic.example.com/api/class/topSystem.json
```

### 🎯 Using the APIC-MCP Server

Once configured with VS Code or Claude Desktop, you can use natural language to interact with your ACI fabric:

#### **In VS Code with MCP Extension:**
```
Ask: "Show me all tenants in my ACI fabric"
Ask: "List EPGs in the 'Production' tenant"
Ask: "Check for contract denies in tenant 'Production'"
Ask: "Generate a security analysis report for tenant 'DMZ'"
```

#### **In Claude Desktop:**
```
Ask: "Authenticate to my APIC and show fabric health"
Ask: "What bridge domains exist in tenant 'Web-Services'?"
Ask: "Check PSIRT advisories for my ACI switches"
Ask: "Generate a report analyzing the 'Database' tenant"
```

## 💡 Usage Examples

### Basic Tenant Analysis
```python
# Get tenant overview
tenants = get_tenants(include_children=True)

# Analyze networking
bridge_domains = get_bridge_domains(tenant_name="MyTenant")
vrfs = get_vrfs(tenant_name="MyTenant")

# Security analysis
contracts = get_contracts(tenant_name="MyTenant")
denies = get_contract_denies_for_tenant(tenant_name="MyTenant")
```

### Security Monitoring
```python
# Check for contract violations
denies = get_contract_denies_for_tenant("production")
if denies['deny_count'] > 0:
    print(f"Found {denies['deny_count']} security violations")
    
# PSIRT vulnerability check
psirt_result = verify_apic_vulnerability()
aci_advisories = check_cisco_aci_switches_psirt("5.2(3e)")
```

### Documentation Generation
```python
# Generate comprehensive tenant report
analysis_content = """
# Tenant Analysis Results
... (analysis content)
"""

doc_result = create_tenant_analysis_document(
    analysis_content=analysis_content,
    tenant_name="Production",
    output_filename="production_analysis"
)
```

## 🔧 Development Guide

### Project Structure
```
mcp-server/
├── apic_mcp_server.py      # Main MCP server with 60+ tools
├── auth_utils.py           # APIC authentication utilities
├── .env.template           # Environment template file
├── README.md               # Project documentation
├── requirements.txt        # Project dependencies
├── LICENSE                 # Project license
└── .vscode/                # VS Code configuration
    ├── mcp.json            # MCP server configuration
    └── settings.json       # VS Code settings
```

### Adding New Tools

1. **Define the Tool Function**
```python
@mcp.tool()
def my_new_tool(parameter1: str, parameter2: Optional[int] = None) -> Dict[str, Any]:
    """
    Description of what this tool does.
    
    :param parameter1: Description of parameter1
    :param parameter2: Optional description of parameter2
    :return: Dictionary with results
    """
    try:
        authenticator = get_authenticator()
        
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first."
            }
        
        # Your tool logic here
        result = authenticator.make_authenticated_request("/api/your-endpoint.json")
        
        return {
            "status": "success",
            "data": result
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Tool failed: {str(e)}"
        }
```

2. **Add Error Handling**
- Always check authentication status
- Use try-catch blocks for API calls
- Return consistent response format
- Log errors appropriately

3. **Document the Tool**
- Add clear docstrings
- Include parameter descriptions
- Provide usage examples
- Update this README

### Code Style Guidelines

- **PEP 8 Compliance**: Follow Python coding standards
- **Type Hints**: Use type annotations for all functions
- **Error Handling**: Implement comprehensive error handling
- **Documentation**: Document all functions and classes
- **Logging**: Use appropriate logging levels

### Testing

```bash
# Run basic functionality test
python -c "
import asyncio
from apic_mcp_server import mcp

async def test():
    print('MCP Server loaded successfully')
    
asyncio.run(test())
"
```

## 🐛 Troubleshooting

### Common Issues

#### 1. **Authentication Failures**
```
Error: "Authentication failed: Invalid credentials"
```
**Solutions:**
- Verify APIC URL is correct and accessible
- Check username/password in .env file
- Ensure APIC certificate is trusted (set VERIFY_SSL=false for testing)
- Check network connectivity to APIC management interface

#### 2. **SSL Certificate Issues**
```
Error: "SSL: CERTIFICATE_VERIFY_FAILED"
```
**Solutions:**
```bash
# Temporary fix for testing
export PYTHONHTTPSVERIFY=0

# Or set in .env
APIC_VERIFY_SSL=false
```

#### 3. **Module Import Errors**
```
Error: "ModuleNotFoundError: No module named 'mcp'"
```
**Solutions:**
```bash
# Install missing dependencies
pip install -r requirements.txt

# Or using uv
uv pip install -r requirements.txt

# Verify installation
python -c "import mcp; print('MCP installed successfully')"
```

#### 4. **APIC API Timeouts**
```
Error: "Request timeout"
```
**Solutions:**
- Check network latency to APIC
- Verify APIC is not overloaded
- Increase timeout in auth_utils.py
- Check firewall rules

#### 5. **Permission Denied**
```
Error: "Insufficient privileges"
```
**Solutions:**
- Verify user has appropriate APIC privileges
- Check user role assignments
- Use admin account for testing
- Review RBAC policies

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Environment Validation

```bash
# Check Python version
python --version  # Should be 3.12+ for best compatibility

# Verify dependencies
pip list | grep -E "(requests|mcp|fastmcp)"

# Test APIC connectivity
curl -k https://your-apic.com/api/aaaLogin
```

### Performance Tuning

- **Connection Pooling**: Reuse APIC sessions
- **Caching**: Cache frequently accessed data
- **Pagination**: Use pagination for large datasets
- **Filtering**: Apply server-side filtering when possible

### Logs and Monitoring

```python
# Enable detailed logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## 🤝 Contributing

### How to Contribute

1. **Fork the Repository**
2. **Create Feature Branch with descriptive name**
   ```bash
   git checkout -b feature/new-feature
   ```
3. **Make Changes**
   - Follow code style guidelines
   - Add comprehensive tests
   - Update documentation
4. **Commit Changes**
   ```bash
   git commit -m "Add new feature"
   ```
5. **Push to Branch**
   ```bash
   git push origin feature/new-feature
   ```
6. **Open Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/mcp-server.git
cd mcp-server

# Install development dependencies
pip install -r requirements.txt
pip install black flake8 pytest
```

### Areas for Contribution

- **New APIC Tools**: Add support for additional APIC classes / use cases
- **Enhanced Analysis**: Improve tenant analysis algorithms
- **UI Improvements**: Create web interface for the server
- **Documentation**: Improve examples and tutorials
- **Testing**: Add comprehensive test suite
- **Performance**: Optimize API calls and caching

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](../../issues)
- **Documentation**: This README and inline code comments

## 🔗 Related Resources

- [Cisco ACI Documentation](https://www.cisco.com/c/en/us/support/cloud-systems-management/application-policy-infrastructure-controller-apic/tsd-products-support-series-home.html)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [FastMCP Framework](https://github.com/jlowin/fastmcp)
- [Cisco PSIRT API](https://developer.cisco.com/docs/psirt/)

---

**Made with ❤️ for network automation and ACI management**
