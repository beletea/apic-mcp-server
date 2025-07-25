#!/usr/bin/env python3
"""
Cisco ACI APIC MCP Server

This MCP server provides tools for interacting with Cisco ACI APIC controllers,
including authentication, fetching classes, and managing APIC resources.
It uses the FastMCP framework to create a server that can be queried via HTTP requests. 
It supports authentication, fetching tenants, application profiles, EPGs, fabric nodes,
bridge domains, contracts, VRFs, and more.
It also includes tools for analyzing tenant configurations, checking denied logs,   
and verifying APIC vulnerabilities using the PSIRT API.
It is designed to work with environment variables for configuration, making it suitable for both development and production environments.
"""

import os
import json
import logging
import re
from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup
from auth_utils import APICAuthenticator, APICAuthenticationError
from docx.enum.table import WD_TABLE_ALIGNMENT

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server instance
mcp = FastMCP("Cisco ACI APIC Server")

# Global authenticator instance (will be initialized when needed)
_authenticator: Optional[APICAuthenticator] = None

def get_authenticator() -> APICAuthenticator:
    """Get or create the global authenticator instance."""
    global _authenticator
    if _authenticator is None:
        apic_url = os.getenv('APIC_URL', 'https://your-apic.example.com')
        verify_ssl = os.getenv('APIC_VERIFY_SSL', 'false').lower() == 'true'
        username = os.getenv('APIC_USERNAME', 'admin')
        password = os.getenv('APIC_PASSWORD', 'password')
        _authenticator = APICAuthenticator(apic_url, verify_ssl)
        # Set credentials if APICAuthenticator supports it
        if hasattr(_authenticator, 'username'):
            _authenticator.username = username
        if hasattr(_authenticator, 'password'):
            _authenticator.password = password
    return _authenticator

@mcp.tool()
def authenticate_apic(apic_url: str, username: str, password: str, verify_ssl: bool = False) -> Dict[str, Any]:
    """
    Authenticate to a Cisco ACI APIC controller and establish a session using .env variables.
    
    :param apic_url: The APIC controller URL (e.g., 'https://apic.example.com')
    :param username: APIC username
    :param password: APIC password  
    :param verify_ssl: Whether to verify SSL certificates (default: False for lab environments)
    :return: Authentication information including JWT token and session details
    """
    global _authenticator

    # Use .env credentials if arguments are not provided
    env_apic_url = os.getenv('APIC_URL', 'https://your-apic.example.com')
    env_username = os.getenv('APIC_USERNAME', 'admin')
    env_password = os.getenv('APIC_PASSWORD', 'password')
    env_verify_ssl = os.getenv('APIC_VERIFY_SSL', 'false').lower() == 'true'

    apic_url = apic_url or env_apic_url
    username = username or env_username
    password = password or env_password
    verify_ssl = verify_ssl or env_verify_ssl

    try:
        _authenticator = APICAuthenticator(apic_url, verify_ssl)
        # Set credentials if APICAuthenticator supports it
        if hasattr(_authenticator, 'username'):
            _authenticator.username = username
        if hasattr(_authenticator, 'password'):
            _authenticator.password = password
        auth_info = _authenticator.authenticate(username, password)
        
        # Directly use the dictionary returned by the authenticator
        return auth_info
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"Authentication failed: {str(e)}",
            "apic_url": apic_url,
            "username": username
        }
    except Exception as e:
        return {
            "status": "error", 
            "message": f"Unexpected error: {str(e)}",
            "apic_url": apic_url,
            "username": username
        }

@mcp.tool()
def fetch_apic_class(class_name: str, query_params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Fetch objects of a specific APIC class.
    
    :param class_name: The APIC class name (e.g., 'fvTenant', 'fvAp', 'fvAEPg', 'fabricNode')
    :param query_params: Optional query parameters (e.g., {'rsp-subtree': 'children'})
    :return: APIC API response containing the requested class objects
    """
    try:
        authenticator = get_authenticator()
        
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first using authenticate_apic tool.",
                "class_name": class_name
            }
        
        # Build the API endpoint
        endpoint = f"/api/class/{class_name}.json"
        
        # Add query parameters if provided
        if query_params:
            params = "&".join([f"{k}={v}" for k, v in query_params.items()])
            endpoint += f"?{params}"
        
        # Make the API request
        response = authenticator.make_authenticated_request(endpoint)
        
        # Process the response
        objects = response.get('imdata', [])
        
        return {
            "status": "success",
            "message": f"Successfully fetched {len(objects)} {class_name} objects",
            "class_name": class_name,
            "count": len(objects),
            "endpoint": endpoint,
            "objects": objects
        }
        
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}",
            "class_name": class_name
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
            "class_name": class_name
        }

@mcp.tool()
def get_tenants(include_children: bool = False) -> Dict[str, Any]:
    """
    Get all tenants from the APIC controller.
    
    :param include_children: Whether to include tenant children (Application Profiles, etc.)
    :return: List of tenants with their details
    """
    query_params = {}
    if include_children:
        query_params['rsp-subtree'] = 'children'
    
    return fetch_apic_class('fvTenant', query_params)

@mcp.tool()
def get_application_profiles(tenant_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get application profiles from the APIC controller.
    
    :param tenant_name: Optional tenant name to filter application profiles
    :return: List of application profiles
    """
    query_params = {}
    if tenant_name:
        query_params['query-target-filter'] = f'eq(fvAp.name,"{tenant_name}")'
    
    return fetch_apic_class('fvAp', query_params)

@mcp.tool()
def get_epgs(tenant_name: Optional[str] = None, app_profile_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get Endpoint Groups (EPGs) from the APIC controller.
    
    :param tenant_name: Optional tenant name to filter EPGs
    :param app_profile_name: Optional application profile name to filter EPGs
    :return: List of EPGs
    """
    query_params = {}
    
    # Build filter if tenant or app profile specified
    filters = []
    if tenant_name:
        filters.append(f'wcard(fvAEPg.dn,"tn-{tenant_name}")')
    if app_profile_name:
        filters.append(f'wcard(fvAEPg.dn,"ap-{app_profile_name}")')
    
    if filters:
        query_params['query-target-filter'] = 'and(' + ','.join(filters) + ')'
        
    # Include fvRsBd children to get Bridge Domain mapping
    query_params['rsp-subtree'] = 'children'
    query_params['rsp-subtree-class'] = 'fvRsBd'
    
    return fetch_apic_class('fvAEPg', query_params)

@mcp.tool()
def get_fabric_nodes() -> Dict[str, Any]:
    """
    Get fabric nodes (switches, controllers) from the APIC controller with OOB and INB management IPs.
    
    :return: List of fabric nodes with their details including management IPs
    """
    nodes_result = fetch_apic_class('fabricNode')
    if nodes_result.get('status') != 'success':
        return nodes_result
    
    nodes = nodes_result.get('objects', [])
    
    # Get OOB management IPs from mgmtRsOoBStNode
    oob_result = fetch_apic_class('mgmtRsOoBStNode')
    oob_ips = {}
    if oob_result.get('status') == 'success':
        for oob_obj in oob_result.get('objects', []):
            oob_attrs = oob_obj.get('mgmtRsOoBStNode', {}).get('attributes', {})
            tdn = oob_attrs.get('tDn', '')
            # Extract node ID from tDn like: topology/pod-1/node-101
            if 'node-' in tdn:
                node_id = tdn.split('node-')[1]
                oob_ips[node_id] = oob_attrs.get('addr', '')
    
    # Get INB management IPs from mgmtRsInBStNode
    inb_result = fetch_apic_class('mgmtRsInBStNode')
    inb_ips = {}
    if inb_result.get('status') == 'success':
        for inb_obj in inb_result.get('objects', []):
            inb_attrs = inb_obj.get('mgmtRsInBStNode', {}).get('attributes', {})
            tdn = inb_attrs.get('tDn', '')
            # Extract node ID from tDn like: topology/pod-1/node-101
            if 'node-' in tdn:
                node_id = tdn.split('node-')[1]
                inb_ips[node_id] = inb_attrs.get('addr', '')
    
    # Enrich nodes with management IPs
    enriched_nodes = []
    for node_obj in nodes:
        attrs = node_obj.get('fabricNode', {}).get('attributes', {})
        node_id = attrs.get('id', '')
        
        # Add OOB/INB info to node attributes
        attrs['oobMgmtAddr'] = oob_ips.get(node_id, '')
        attrs['inbMgmtAddr'] = inb_ips.get(node_id, '')
        
        enriched_nodes.append({'fabricNode': {'attributes': attrs}})
    
    return {
        'status': 'success',
        'message': f"Successfully fetched {len(enriched_nodes)} fabricNode objects with management IPs",
        'class_name': 'fabricNode',
        'count': len(enriched_nodes),
        'objects': enriched_nodes
    }

@mcp.tool()
def get_bridge_domains(tenant_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get bridge domains from the APIC controller.
    
    :param tenant_name: Optional tenant name to filter bridge domains
    :return: List of bridge domains
    """
    query_params = {}
    if tenant_name:
        query_params['query-target-filter'] = f'wcard(fvBD.dn,"tn-{tenant_name}")'
    
    return fetch_apic_class('fvBD', query_params)

@mcp.tool()
def get_contracts(tenant_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get contracts from the APIC controller.
    
    :param tenant_name: Optional tenant name to filter contracts
    :return: List of contracts
    """
    query_params = {}
    if tenant_name:
        query_params['query-target-filter'] = f'wcard(vzBrCP.dn,"tn-{tenant_name}")'
    
    return fetch_apic_class('vzBrCP', query_params)

@mcp.tool()
def get_vrfs(tenant_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get VRFs (Virtual Routing and Forwarding contexts) from the APIC controller.
    
    :param tenant_name: Optional tenant name to filter VRFs
    :return: List of VRFs
    """
    query_params = {}
    if tenant_name:
        query_params['query-target-filter'] = f'wcard(fvCtx.dn,"tn-{tenant_name}")'
    
    return fetch_apic_class('fvCtx', query_params)

@mcp.tool()
def create_apic_object(parent_dn: str, object_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create an APIC object in the fabric. This is a dangerous operation.

    :param parent_dn: The Distinguished Name (DN) of the parent object under which the new object will be created.
                      Example: 'uni/tn-my-tenant/ap-my-app' for creating an EPG.
    :param object_payload: A dictionary representing the object to create.
                           Example: {"fvAEPg": {"attributes": {"name": "my-new-epg"}}}
    :return: The result of the creation operation.
    """
    try:
        authenticator = get_authenticator()
        
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first using authenticate_apic tool."
            }
        
        # The endpoint for creation is the parent's DN
        endpoint = f"/api/mo/{parent_dn}.json"
        
        # The method for creation is POST
        response = authenticator.make_authenticated_request(endpoint, method='POST', payload=object_payload)
        
        # A successful POST usually returns a 200 OK with an empty imdata or some status info.
        # The make_authenticated_request should raise an exception on non-2xx status codes.
        
        return {
            "status": "success",
            "message": f"Successfully sent creation request for object under '{parent_dn}'.",
            "endpoint": endpoint,
            "payload_sent": object_payload,
            "response": response
        }
        
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}",
            "parent_dn": parent_dn
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error during object creation: {str(e)}",
            "parent_dn": parent_dn
        }

@mcp.tool()
def delete_apic_object(object_dn: str) -> Dict[str, Any]:
    """
    Delete an APIC object from the fabric. This is a dangerous operation.

    :param object_dn: The Distinguished Name (DN) of the object to delete.
                      Example: 'uni/tn-my-tenant/ap-my-app/epg-my-new-epg'
    :return: The result of the deletion operation.
    """
    try:
        authenticator = get_authenticator()
        
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first using authenticate_apic tool."
            }
        
        # The endpoint for deletion is the object's DN
        endpoint = f"/api/mo/{object_dn}.json"
        
        # The method for deletion is DELETE
        response = authenticator.make_authenticated_request(endpoint, method='DELETE')
        
        # A successful DELETE usually returns a 200 OK with an empty imdata or some status info.
        
        return {
            "status": "success",
            "message": f"Successfully sent deletion request for object '{object_dn}'.",
            "endpoint": endpoint,
            "response": response
        }
        
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}",
            "object_dn": object_dn
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error during object deletion: {str(e)}",
            "object_dn": object_dn
        }

@mcp.tool()
def search_objects_by_name(object_name: str, class_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Search for APIC objects by name across different classes.
    
    :param object_name: The name to search for
    :param class_filter: Optional class filter (e.g., 'fvTenant' to search only tenants)
    :return: Search results with matching objects
    """
    try:
        authenticator = get_authenticator()
        
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first using authenticate_apic tool.",
                "search_term": object_name
            }
        
        # Common classes to search
        search_classes = ['fvTenant', 'fvAp', 'fvAEPg', 'fvBD', 'fvCtx', 'vzBrCP'] 
        
        if class_filter:
            search_classes = [class_filter]
        
        results = {}
        total_found = 0
        
        for class_name in search_classes:
            try:
                endpoint = f"/api/class/{class_name}.json?query-target-filter=eq({class_name}.name,\"{object_name}\")"
                response = authenticator.make_authenticated_request(endpoint)
                objects = response.get('imdata', [])
                
                if objects:
                    results[class_name] = {
                        "count": len(objects),
                        "objects": objects
                    }
                    total_found += len(objects)
                    
            except Exception as e:
                logger.warning(f"Failed to search class {class_name}: {e}")
                continue
        
        return {
            "status": "success",
            "message": f"Found {total_found} objects matching '{object_name}'",
            "search_term": object_name,
            "class_filter": class_filter,
            "total_found": total_found,
            "results": results
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Search failed: {str(e)}",
            "search_term": object_name
        }

@mcp.tool()
def get_apic_status() -> Dict[str, Any]:
    """
    Get the current APIC authentication status and session information.
    
    :return: Current authentication status and session details
    """
    try:
        authenticator = get_authenticator()
        
        if not authenticator.token:
            return {
                "status": "not_authenticated",
                "message": "No active APIC session. Please authenticate first.",
                "apic_url": authenticator.apic_url,
                "verify_ssl": authenticator.verify_ssl
            }
        
        # Try to make a simple API call to verify the session is still valid
        try:
            response = authenticator.make_authenticated_request('/api/class/aaaUser.json?query-target-self')
            user_info = response.get('imdata', [])
            
            return {
                "status": "authenticated",
                "message": "Active APIC session",
                "apic_url": authenticator.apic_url,
                "verify_ssl": authenticator.verify_ssl,
                "token_preview": authenticator.token[:20] + "..." if authenticator.token else "No token",
                "user_info": user_info[0] if user_info else "No user info available"
            }
            
        except APICAuthenticationError:
            return {
                "status": "session_expired",
                "message": "APIC session has expired. Please re-authenticate.",
                "apic_url": authenticator.apic_url,
                "verify_ssl": authenticator.verify_ssl
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to check status: {str(e)}"
        }

@mcp.tool()
def logout_apic() -> Dict[str, Any]:
    """
    Logout from the APIC controller and invalidate the current session.
    
    :return: Logout status
    """
    global _authenticator
    
    try:
        if _authenticator and _authenticator.token:
            success = _authenticator.logout()
            _authenticator = None  # Clear the global authenticator
            
            if success:
                return {
                    "status": "success",
                    "message": "Successfully logged out from APIC"
                }
            else:
                return {
                    "status": "warning",
                    "message": "Logout completed but may not have been clean"
                }
        else:
            return {
                "status": "info",
                "message": "No active session to logout"
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"Logout failed: {str(e)}"
        }

# Resources for common APIC information
@mcp.resource("apic://status")
def apic_status_resource() -> str:
    """
    Resource providing current APIC connection status.
    """
    status = get_apic_status()
    return json.dumps(status, indent=2)

@mcp.resource("apic://classes") # Resource listing common APIC classes
def apic_classes_resource() -> str:
    """
    Resource listing common APIC classes that can be queried.
    """
    classes = {
        "Tenant Management": {
            "fvTenant": "Tenants - Top-level containers for policies",
            "fvAp": "Application Profiles - Collections of EPGs", 
            "fvAEPg": "Endpoint Groups - Collections of endpoints"
        },
        "Networking": {
            "fvBD": "Bridge Domains - Layer 2 forwarding domains",
            "fvCtx": "VRFs - Virtual Routing and Forwarding contexts",
            "fvSubnet": "Subnets - IP subnets within bridge domains"
        },
        "Policy": {
            "vzBrCP": "Contracts - Communication policies between EPGs",
            "vzSubj": "Contract Subjects - Groups of filters in contracts",
            "vzFilter": "Filters - Access control rules"
        },
        "Fabric": {
            "fabricNode": "Fabric Nodes - Switches and controllers",
            "fabricLink": "Fabric Links - Physical connections",
            "fabricPod": "Fabric Pods - Groups of nodes"
        },
        "Physical": {
            "physDomP": "Physical Domains - Physical connectivity domains",
            "infraAccPortP": "Access Port Profiles - Port configurations",
            "infraNodeP": "Node Profiles - Switch configurations"
        }
    }
    return json.dumps(classes, indent=2)

@mcp.prompt()
def analyze_apic_tenant(tenant_name: str) -> str:
    """
    Generate a prompt for analyzing an APIC tenant configuration.
    
    :param tenant_name: The name of the tenant to analyze
    :return: A prompt asking the LLM to analyze the tenant
    """
    return f"""Please analyze the Cisco ACI tenant '{tenant_name}' configuration. 

Consider examining:
1. Application Profiles and their EPGs
2. Bridge Domains and their subnets
3. VRFs and routing configuration
4. Contracts and security policies
5. Physical domain associations
6. Overall design patterns and best practices

Use the available APIC MCP tools to gather this information and provide insights about the tenant's architecture, potential issues, and recommendations for improvement."""

@mcp.tool()
def get_denied_logs_for_tenant(tenant_name: str) -> Dict[str, Any]:
    """
    Check for denied logs (audit logs) for a specific tenant.
    Returns a list of denied events from APIC audit logs (aaaModLR) filtered by tenant.
    """
    # APIC audit logs are in class 'aaaModLR' (Modification Log Record)
    # Filter by tenant DN
    query_params = {
        'query-target-filter': f'wcard(aaaModLR.dn,"tn-{tenant_name}")'
    }
    result = fetch_apic_class('aaaModLR', query_params)
    if result.get('status') != 'success':
        return {
            'status': 'error',
            'message': f"Failed to fetch denied logs: {result.get('message')}"
        }
    # Filter for denied events
    denied_events = []
    for obj in result.get('objects', []):
        attrs = obj.get('aaaModLR', {}).get('attributes', {})
        if 'denied' in attrs.get('descr', '').lower() or attrs.get('status', '').lower() == 'denied':
            denied_events.append({
                'timestamp': attrs.get('modTs', ''),
                'user': attrs.get('user', ''),
                'descr': attrs.get('descr', ''),
                'dn': attrs.get('dn', '')
            })
    return {
        'status': 'success',
        'tenant': tenant_name,
        'denied_count': len(denied_events),
        'denied_events': denied_events
    }

@mcp.tool()
def get_contract_denies_for_tenant(tenant_name: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Get contract deny events (L3 packet drops) for a specific tenant, including source and destination EPGs.
    Returns a list of denied contract events from the 'acllogDropL3Pkt' class.
    """
    try:
        authenticator = get_authenticator()
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first using authenticate_apic tool.",
            }

        # The class acllogDropL3Pkt is not a standard queryable class via /api/class/.
        # It's found under a specific path per tenant.
        endpoint = f"/api/node/class/ndbgs/acllog/tn-{tenant_name}/acllogDropL3Pkt.json"
        
        response = authenticator.make_authenticated_request(endpoint)
        
        objects = response.get('imdata', [])
        
        contract_denies = []
        for obj in objects:
            attrs = obj.get('acllogDropL3Pkt', {}).get('attributes', {})
            src_ip = attrs.get('srcIp', '')
            dst_ip = attrs.get('dstIp', '')

            # If ip_address is provided, filter by it
            if ip_address and ip_address not in (src_ip, dst_ip):
                continue

            contract_denies.append({
                'timestamp': attrs.get('modTs', ''),
                'src_ip': attrs.get('srcIp', ''),
                'dst_ip': attrs.get('dstIp', ''),
                'src_epg': attrs.get('srcEpgName', 'N/A'),
                'dst_epg': attrs.get('dstEpgName', 'N/A'),
                'vrf': attrs.get('vrf', 'N/A'),
                'protocol': attrs.get('proto', ''),
                'src_port': attrs.get('srcPort', ''),
                'dst_port': attrs.get('dstPort', ''),
                'action': attrs.get('action', ''),
                'filter_name': attrs.get('fltId', ''),
                'Source_interface': attrs.get('srcIntf', 'N/A'),
                'src_pc_tag': attrs.get('srcPcTag', 'N/A'),
                'dst_pc_tag': attrs.get('dstPcTag', 'N/A'),
                'dn': attrs.get('dn', 'N/A')
            })

        return {
            'status': 'success',
            'tenant': tenant_name,
            'deny_count': len(contract_denies),
            'denies': contract_denies
        }
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
        }


@mcp.tool()
def get_contract_permit_logs_for_tenant(tenant_name: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Get contract permit events (L3 packet permits) for a specific tenant.
    Optionally filters for a specific IP address in source or destination.
    Returns a list of permitted contract events from the 'acllogPermitL3Pkt' class.
    """
    try:
        authenticator = get_authenticator()
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first using authenticate_apic tool.",
            }

        # The class acllogPermitL3Pkt is found under a specific path per tenant.
        endpoint = f"/api/node/class/ndbgs/acllog/tn-{tenant_name}/acllogPermitL3Pkt.json"
        
        response = authenticator.make_authenticated_request(endpoint)
        
        objects = response.get('imdata', [])
        
        permit_logs = []
        for obj in objects:
            attrs = obj.get('acllogPermitL3Pkt', {}).get('attributes', {})
            src_ip = attrs.get('srcIp', '')
            dst_ip = attrs.get('dstIp', '')

            # If ip_address is provided, filter by it
            if ip_address and ip_address not in (src_ip, dst_ip):
                continue

            permit_logs.append({
                'timestamp': attrs.get('modTs', ''),
                'src_ip': attrs.get('srcIp', ''),
                'dst_ip': attrs.get('dstIp', ''),
                'src_epg': attrs.get('srcEpgName', 'N/A'),
                'dst_epg': attrs.get('dstEpgName', 'N/A'),
                'vrf': attrs.get('vrf', 'N/A'),
                'protocol': attrs.get('proto', ''),
                'src_port': attrs.get('srcPort', ''),
                'dst_port': attrs.get('dstPort', ''),
                'action': attrs.get('action', ''),
                'filter_name': attrs.get('fltId', ''),
                'Source_interface': attrs.get('srcIntf', 'N/A'),
                'src_pc_tag': attrs.get('srcPcTag', 'N/A'),
                'dst_pc_tag': attrs.get('dstPcTag', 'N/A'),
                'dn': attrs.get('dn', 'N/A')
            })

        return {
            'status': 'success',
            'tenant': tenant_name,
            'ip_filter': ip_address,
            'permit_count': len(permit_logs),
            'permits': permit_logs
        }
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
        }


# Tool: Check operational status of interfaces for a given node
@mcp.tool()
def get_node_interface_status() -> Dict[str, Any]:
    """
    Get operational status of all physical interfaces for all nodes.
    :return: Dictionary of node IDs to lists of interfaces and their operational status
    """
    # Fetch all ethpmPhysIf objects
    result = fetch_apic_class('ethpmPhysIf')
    if result.get('status') != 'success':
        return {
            'status': 'error',
            'message': f"Failed to fetch interfaces: {result.get('message')}"
        }
    node_interfaces = {}
    for obj in result.get('objects', []):
        attrs = obj.get('ethpmPhysIf', {}).get('attributes', {})
        dn = attrs.get('dn', '')
        # Extract node ID from DN (e.g., topology/pod-1/node-101/sys/ethpmPhysIf-[eth1/1])
        node_id = ''
        parts = dn.split('/')
        for i, part in enumerate(parts):
            if part.startswith('node-'):
                node_id = part.replace('node-', '')
                break
        if node_id:
            iface = {
                'id': attrs.get('id', ''),
                'dn': dn,
                'operSt': attrs.get('operSt', ''),
                'operSpeed': attrs.get('operSpeed', ''),
                'operDuplex': attrs.get('operDuplex', ''),
                'operMac': attrs.get('operMac', ''),
                'operVlans': attrs.get('operVlans', ''),
                'operMode': attrs.get('operMode', ''),
                'descr': attrs.get('descr', ''),
            }
            node_interfaces.setdefault(node_id, []).append(iface)
    return {
        'status': 'success',
        'node_count': len(node_interfaces),
        'nodes': node_interfaces
    }

# verify APIC vulnerabilities using PSIRT API
@mcp.tool()
def verify_apic_vulnerability() -> dict:
    """
    Verify APIC vulnerabilities using the PSIRT API endpoint base_url/product?product=apic.
    :return: Dictionary with vulnerability/advisory results
    """
    base_url = os.getenv('MY_PSIRT_API_URL', '')
    client_id = os.getenv('MY_PSIRT_CLIENT_ID', '')
    client_secret = os.getenv('MY_PSIRT_CLIENT_SECRET', '')
    if not base_url or not client_id or not client_secret:
        return {
            'status': 'error',
            'message': 'Missing PSIRT API configuration in environment.'
        }
    # Step 1: Get OAuth token
    token_url = f"https://id.cisco.com/oauth2/default/v1/token"
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        token_resp = requests.post(token_url, data=token_data, headers=token_headers, timeout=10)
        if not token_resp.ok:
            return {
                'status': 'error',
                'message': f'Failed to get OAuth token: {token_resp.text}'
            }
        token_json = token_resp.json()
        access_token = token_json.get('access_token')
        if not access_token:
            return {
                'status': 'error',
                'message': 'No access token received from Cisco OAuth.'
            }
        # Step 2: Call product endpoint to get APIC vulnerabilities
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
        product_url = f"{base_url}/product?product=apic"
        resp = requests.get(product_url, headers=headers, timeout=10)
        if not resp.ok:
            return {
                'status': 'error',
                'message': f'Failed to fetch APIC vulnerabilities: {resp.text}'
            }
        data = resp.json()
        return {
            'status': 'success',
            'product': 'apic',
            'vulnerabilities': data
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Failed to verify APIC vulnerabilities: {str(e)}'
        }
    
# Tool: Check if ACI version is in PSIRT database   
@mcp.tool()
def is_aci_version_in_psirt(version: str) -> dict:
    """
    Verify if the given ACI version is present in the PSIRT database using the OS_data endpoint.
    :param version: ACI code version (e.g., '5.2(3e)')
    :return: Dictionary indicating presence and available versions
    """
    base_url = os.getenv('MY_PSIRT_API_URL', '')
    client_id = os.getenv('MY_PSIRT_CLIENT_ID', '')
    client_secret = os.getenv('MY_PSIRT_CLIENT_SECRET', '')
    if not base_url or not client_id or not client_secret:
        return {
            'status': 'error',
            'message': 'Missing PSIRT API configuration in environment.'
        }
    # Step 1: Get OAuth token
    token_url = f"https://id.cisco.com/oauth2/default/v1/token"
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        token_resp = requests.post(token_url, data=token_data, headers=token_headers, timeout=10)
        if not token_resp.ok:
            return {
                'status': 'error',
                'message': f'Failed to get OAuth token: {token_resp.text}'
            }
        token_json = token_resp.json()
        access_token = token_json.get('access_token')
        if not access_token:
            return {
                'status': 'error',
                'message': 'No access token received from Cisco OAuth.'
            }
        # Step 2: Call OS_data endpoint to get available versions
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
        os_data_url = f"{base_url}/OS_version/OS_data?OSType=aci"
        resp = requests.get(os_data_url, headers=headers, timeout=10)
        if not resp.ok:
            return {
                'status': 'error',
                'message': f'Failed to fetch OS_data: {resp.text}'
            }
        data = resp.json()
        # Extract available versions
        available_versions = data.get('OSVersions', [])
        found = version in available_versions
        return {
            'status': 'success',
            'version': version,
            'found': found,
            'available_versions': available_versions
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Failed to verify version in PSIRT database: {str(e)}'
        }
# Tool: Check Cisco ACI switches PSIRT advisories
@mcp.tool()
def check_cisco_aci_switches_psirt(os_version: str) -> dict:
    """
    Check PSIRT (Product Security Incident Response Team) Cisco Security Advisories for a given product and code version.
    Uses service API with base URL and credentials from .env.
    :param ostype: Operating system type (e.g., 'aci', 'nxos', 'iosxe')
    :param code_version: Code version (e.g., '5.2(3e)')
    :return: Dictionary with PSIRT and advisory results
    """
    import requests
    base_url = os.getenv('MY_PSIRT_API_URL', '')
    client_id = os.getenv('MY_PSIRT_CLIENT_ID', '')
    client_secret = os.getenv('MY_PSIRT_CLIENT_SECRET', '')
    if not base_url or not client_id or not client_secret:
        return {
            'status': 'error',
            'message': 'Missing PSIRT API configuration in environment.'
        }
    # Step 1: Get OAuth token
    token_url = f"https://id.cisco.com/oauth2/default/v1/token"
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        token_resp = requests.post(token_url, data=token_data, headers=token_headers, timeout=10)
        if not token_resp.ok:
            return {
                'status': 'error',
                'message': f'Failed to get OAuth token: {token_resp.text}'
            }
        token_json = token_resp.json()
        access_token = token_json.get('access_token')
        if not access_token:
            return {
                'status': 'error',
                'message': 'No access token received from Cisco OAuth.'
            }
        # Step 2: Call PSIRT/advisory API with Bearer token
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
        psirt_url = f"{base_url}/OSType/aci?version={os_version}"
        psirt_resp = requests.get(psirt_url, headers=headers, timeout=10)
        print(f"PSIRT Response: {psirt_resp}")
        psirt_data = psirt_resp.json() if psirt_resp.ok else {'error': psirt_resp.text}
        return {
            'status': 'success',
            'product': 'Cisco ACI',
            'version': os_version,
            'psirt': psirt_data,
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Failed to fetch PSIRT or advisory: {str(e)}'
        }

@mcp.tool()
def get_nexus_9000_field_notices(device_models: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Scrapes the Cisco website for field notices related to Nexus 9000 Series Switches.
    Scrapes ALL field notices from the page and filters for ones relevant to the provided device models.
    :param device_models: List of device model strings without N9K-C prefix
    :return: A dictionary containing a list of field notices with their titles and URLs.
    """
    url = "https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-field-notices-list.html"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        import re
        
        def normalize_model(model):
            # Remove N9K-C prefix, spaces, and make uppercase for comparison
            return model.upper().replace('N9K-C', '').replace(' ', '').replace('_', '').replace('-', '')

        # First, scrape ALL field notices from the page
        all_notices = []
        
        # Find all links that could be field notices
        all_links = soup.find_all('a')
        for link in all_links:
            href = link.get('href', '')
            title = link.get_text(strip=True)
            
            # Check if this looks like a field notice
            if ('FN' in title.upper() or 
                'field-notice' in href.lower() or 
                'fn-' in href.lower() or
                'field notice' in title.lower()):
                
                notice_url = href
                if not notice_url.startswith('http'):
                    notice_url = f"https://www.cisco.com{notice_url}"
                
                # Try to extract date
                date = "N/A"
                list_item = link.find_parent('li')
                if list_item:
                    item_text = list_item.get_text()
                    date_match = re.search(r'\b(\d{1,2}-[A-Za-z]{3}-\d{4})\b|\b([A-Za-z]+\s+\d{1,2},\s+\d{4})\b', item_text)
                    if date_match:
                        date = date_match.group(0)
                
                # Try to determine which product/model this relates to
                product_series = "Unknown"
                parent_heading = None
                
                # Look for parent heading
                current = link.parent
                while current and not parent_heading:
                    for sibling in current.find_previous_siblings():
                        if sibling.name and re.match('^h[1-6]$', sibling.name):
                            parent_heading = sibling.get_text(strip=True)
                            break
                    current = current.parent
                
                if parent_heading:
                    product_series = parent_heading
                
                all_notices.append({
                    "title": title,
                    "url": notice_url,
                    "last_updated": date,
                    "product_series": product_series,
                    "full_text": title + " " + (list_item.get_text() if list_item else "")
                })
        
        # Remove duplicates based on URL
        unique_notices = []
        seen_urls = set()
        for notice in all_notices:
            if notice['url'] not in seen_urls:
                unique_notices.append(notice)
                seen_urls.add(notice['url'])
        
        # If device_models is provided, filter for relevant notices
        relevant_notices = []
        if device_models:
            normalized_device_models = set()
            for model in device_models:
                normalized_device_models.add(normalize_model(model))
            
            for notice in unique_notices:
                # Check if any of the device models appear in the notice
                notice_text = (notice['title'] + " " + notice['product_series'] + " " + notice['full_text']).upper()
                
                # Remove common prefixes/suffixes for matching
                notice_text_clean = notice_text.replace('N9K-C', '').replace('CISCO', '').replace('NEXUS', '').replace('SWITCH', '')
                
                is_relevant = False
                for model in device_models:
                    # Try different variations of the model name
                    model_variations = [
                        model,
                        f"N9K-C{model}",
                        f"N9K-{model}",
                        f"NEXUS {model}",
                        f"9K-{model}",
                        normalize_model(model)
                    ]
                    
                    for variation in model_variations:
                        if variation.upper() in notice_text_clean:
                            is_relevant = True
                            break
                    
                    if is_relevant:
                        break
                
                if is_relevant:
                    # Remove the full_text field before adding to results
                    notice_copy = notice.copy()
                    notice_copy.pop('full_text', None)
                    relevant_notices.append(notice_copy)
            
            return {
                "status": "success",
                "total_notices_found": len(unique_notices),
                "relevant_notices_count": len(relevant_notices),
                "device_models_searched": device_models,
                "field_notices": relevant_notices
            }
        else:
            # Return all notices if no device models specified
            for notice in unique_notices:
                notice.pop('full_text', None)
            
            return {
                "status": "success",
                "total_notices_found": len(unique_notices),
                "field_notices": unique_notices
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Failed to fetch the webpage: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred during scraping: {str(e)}"
        }

@mcp.tool()
def get_apic_field_notices() -> Dict[str, Any]:
    """
    Scrapes the Cisco website for field notices related to APIC controllers.
    Searches the APIC support page for all field notices and technical bulletins.
    :return: A dictionary containing a list of field notices with their titles and URLs.
    """
    url = "https://www.cisco.com/c/en/us/support/cloud-systems-management/application-policy-infrastructure-controller-apic/tsd-products-support-series-home.html"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        import re
        
        all_notices = []
        
        # Find all links that could be field notices or technical bulletins
        all_links = soup.find_all('a')
        for link in all_links:
            href = link.get('href', '')
            title = link.get_text(strip=True)
            
            # Check if this looks like a field notice or technical bulletin
            if ('FN' in title.upper() or 
                'field-notice' in href.lower() or 
                'field notice' in title.lower() or
                'fn-' in href.lower() or
                'technical bulletin' in title.lower() or
                'bulletin' in title.lower() or
                'tsd' in href.lower()):
                
                notice_url = href
                if not notice_url.startswith('http'):
                    notice_url = f"https://www.cisco.com{notice_url}"
                
                # Try to extract date
                date = "N/A"
                list_item = link.find_parent('li')
                if list_item:
                    item_text = list_item.get_text()
                    date_match = re.search(r'\b(\d{1,2}-[A-Za-z]{3}-\d{4})\b|\b([A-Za-z]+\s+\d{1,2},\s+\d{4})\b|\b(\d{2}/\d{2}/\d{4})\b', item_text)
                    if date_match:
                        date = date_match.group(0)
                
                # Try to determine the type of notice
                notice_type = "Unknown"
                if 'field notice' in title.lower() or 'fn' in title.upper():
                    notice_type = "Field Notice"
                elif 'bulletin' in title.lower():
                    notice_type = "Technical Bulletin"
                elif 'advisory' in title.lower():
                    notice_type = "Advisory"
                
                # Try to determine which product/component this relates to
                product_component = "APIC"
                if 'server' in title.lower():
                    product_component = "APIC Server"
                elif 'software' in title.lower():
                    product_component = "APIC Software"
                elif 'hardware' in title.lower():
                    product_component = "APIC Hardware"
                
                all_notices.append({
                    "title": title,
                    "url": notice_url,
                    "last_updated": date,
                    "type": notice_type,
                    "component": product_component
                })
        
        # Remove duplicates based on URL
        unique_notices = []
        seen_urls = set()
        for notice in all_notices:
            if notice['url'] not in seen_urls:
                unique_notices.append(notice)
                seen_urls.add(notice['url'])
        
        # Sort by type and title
        unique_notices.sort(key=lambda x: (x['type'], x['title']))
        
        return {
            "status": "success",
            "total_notices_found": len(unique_notices),
            "source_url": url,
            "field_notices": unique_notices
        }
            
    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Failed to fetch the webpage: {str(e)}",
            "source_url": url
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred during scraping: {str(e)}",
            "source_url": url
        }

@mcp.prompt()
def analyze_L3out_tenant(tenant_name: str, L3out_name: str) -> str:
    """
    Generate a prompt for analyzing an APIC L3Out configuration within a tenant.

    :param tenant_name: The name of the tenant to analyze
    :param L3out_name: The name of the L3Out to analyze
    :return: A prompt asking the LLM to analyze the L3Out
    """
    return f"""Please analyze the Cisco ACI L3Out '{L3out_name}' configuration within the tenant '{tenant_name}'.

Consider examining:
1. the vrf, L3 Domain, routing protocol for '{L3out_name}' in the {tenant_name}
2. logical node profile and logical interface profiles for '{L3out_name}' in the {tenant_name}
3. external EPGs with their associated contracts and address & route control scopes and External EPG classification for '{L3out_name}' in the {tenant_name}
4. check if there are any other l3outs with in same vrf with the same external EPG subnets for subnet overlapping
5. Bridge Domains and their subnets associated with the l3out '{L3out_name}' in the {tenant_name}
6. Contracts and security policies for '{L3out_name}' external EPGs in the {tenant_name}
7. Overall design patterns and best practices for '{L3out_name}' in the {tenant_name}
8. L3Out configuration details such as routing protocols, external networks, and connectivity for '{L3out_name}' in the {tenant_name}
9. Shadow object detection and potential issues for '{L3out_name}' in the {tenant_name}
10. Any denied logs or contract denies related to the L3Out '{L3out_name}' in the {tenant_name}

Use visually appealing diagrams to represent the L3Out architecture and its relationships with other components in the tenant.
Use the available APIC MCP tools to gather this information and provide insights about the tenant's architecture, potential issues, and recommendations for improvement."""


if __name__ == "__main__":
    import asyncio
    
    async def run_server():
        """Run the MCP server."""
        await mcp.run()
    
    # Run the server
    asyncio.run(run_server())

