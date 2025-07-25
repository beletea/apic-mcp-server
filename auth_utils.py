#!/usr/bin/env python3
"""
Cisco ACI APIC Authentication Utility

This module provides authentication utilities for connecting to Cisco ACI APIC controllers.
It handles JWT token-based authentication, session management, and API request functionality.
All configuration is read from environment variables for security and flexibility.
"""

import os
import json
import logging
import requests
import urllib3
from typing import Dict, Any, Optional, Union
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Disable SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class APICAuthenticationError(Exception):
    """Custom exception for APIC authentication errors."""
    pass


class APICAuthenticator:
    """
    Cisco ACI APIC Authentication and Session Management Class
    
    This class handles authentication to Cisco ACI APIC controllers using
    username/password authentication and JWT token management.
    """
    
    def __init__(self, apic_url: Optional[str] = None, verify_ssl: Optional[bool] = None, 
                 timeout: Optional[int] = None):
        """
        Initialize the APIC Authenticator.
        
        Args:
            apic_url: APIC controller URL (defaults to APIC_URL env var)
            verify_ssl: Whether to verify SSL certificates (defaults to APIC_VERIFY_SSL env var)
            timeout: Request timeout in seconds (defaults to APIC_TIMEOUT env var)
        """
        # Load configuration from environment variables
        self.apic_url = apic_url or os.getenv('APIC_URL', 'https://your-apic.example.com')
        self.username = os.getenv('APIC_USERNAME', 'admin')
        self.password = os.getenv('APIC_PASSWORD', 'password')
        self.verify_ssl = verify_ssl if verify_ssl is not None else os.getenv('APIC_VERIFY_SSL', 'false').lower() == 'true'
        self.timeout = timeout or int(os.getenv('APIC_TIMEOUT', '30'))
        
        # Authentication state
        self.token = None
        self.session_id = None
        self.token_expiry = None
        self.user_domain = None
        self.apic_version = None
        self.apic_build_time = None
        self.apic_node = None
        
        # Request session for connection pooling
        self.session = requests.Session()
        
        # Clean up APIC URL format
        self.apic_url = self.apic_url.rstrip('/')
        
        logger.info(f"APIC Authenticator initialized for {self.apic_url}")
    
    def authenticate(self, username: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Authenticate to the APIC controller and obtain a JWT token.
        
        Args:
            username: APIC username (optional, uses env var if not provided)
            password: APIC password (optional, uses env var if not provided)
            
        Returns:
            Dictionary containing authentication response and session information
            
        Raises:
            APICAuthenticationError: If authentication fails
        """
        # Use provided credentials or fall back to instance/env vars
        auth_username = username or self.username
        auth_password = password or self.password
        
        # Prepare authentication payload
        auth_payload = {
            "aaaUser": {
                "attributes": {
                    "name": auth_username,
                    "pwd": auth_password
                }
            }
        }
        
        # Authentication endpoint
        auth_url = f"{self.apic_url}/api/aaaLogin.json"
        
        try:
            logger.info(f"Attempting authentication to {self.apic_url} as user '{auth_username}'")
            
            # Make authentication request
            response = self.session.post(
                auth_url,
                json=auth_payload,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse response
            auth_data = response.json()
            
            # Check for APIC-specific errors
            if 'imdata' not in auth_data:
                raise APICAuthenticationError("Invalid response format from APIC")
            
            imdata = auth_data.get('imdata', [])
            if not imdata:
                raise APICAuthenticationError("No authentication data in response")
            
            # Extract authentication information
            auth_info = imdata[0]
            if 'aaaLogin' not in auth_info:
                # Check for error response
                if 'error' in auth_info:
                    error_attrs = auth_info['error']['attributes']
                    error_msg = error_attrs.get('text', 'Unknown authentication error')
                    raise APICAuthenticationError(f"Authentication failed: {error_msg}")
                else:
                    raise APICAuthenticationError("Unexpected response format")
            
            login_attrs = auth_info['aaaLogin']['attributes']
            
            # Store authentication details
            self.token = login_attrs.get('token')
            self.session_id = login_attrs.get('urlToken') or login_attrs.get('sessionId')
            self.user_domain = login_attrs.get('userDomain', '')
            self.apic_version = login_attrs.get('version', 'Unknown')
            self.apic_build_time = login_attrs.get('buildTime', 'Unknown')
            self.apic_node = login_attrs.get('node', 'Unknown')
            
            # Calculate token expiry (APIC tokens typically last 8 hours)
            refresh_timeout = int(login_attrs.get('refreshTimeoutSeconds', 28800))  # Default 8 hours
            self.token_expiry = datetime.now() + timedelta(seconds=refresh_timeout)
            
            # Set default headers for future requests
            self.session.headers.update({
                'Content-Type': 'application/json',
                'APIC-challenge': self.token
            })
            
            logger.info(f"Successfully authenticated to APIC {self.apic_url}")
            logger.info(f"APIC Version: {self.apic_version}, Build: {self.apic_build_time}")
            logger.info(f"Token expires at: {self.token_expiry}")
            
            return {
                "status": "success",
                "message": "Successfully authenticated to APIC",
                "apic_url": self.apic_url,
                "username": auth_username,
                "token_preview": self.token[:20] + "..." if self.token else "No token",
                "session_id": self.session_id,
                "user_domain": self.user_domain,
                "version": self.apic_version,
                "build_time": self.apic_build_time,
                "node": self.apic_node,
                "token_expiry": self.token_expiry.isoformat() if self.token_expiry else None
            }
            
        except requests.exceptions.ConnectTimeout:
            error_msg = f"Connection timeout to {self.apic_url} (timeout: {self.timeout}s)"
            logger.error(error_msg)
            raise APICAuthenticationError(f"Authentication failed: {error_msg}")
            
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Network error: {str(e)}"
            logger.error(error_msg)
            raise APICAuthenticationError(f"Authentication failed: {error_msg}")
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error {e.response.status_code}: {e.response.text}"
            logger.error(error_msg)
            raise APICAuthenticationError(f"Authentication failed: {error_msg}")
            
        except json.JSONDecodeError:
            error_msg = "Invalid JSON response from APIC"
            logger.error(error_msg)
            raise APICAuthenticationError(f"Authentication failed: {error_msg}")
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            raise APICAuthenticationError(f"Authentication failed: {error_msg}")
    
    def is_authenticated(self) -> bool:
        """
        Check if the current session is authenticated and token is valid.
        
        Returns:
            True if authenticated and token is valid, False otherwise
        """
        if not self.token or not self.token_expiry:
            return False
        
        # Check if token has expired (with 5 minute buffer)
        buffer_time = timedelta(minutes=5)
        return datetime.now() < (self.token_expiry - buffer_time)
    
    def refresh_token(self) -> Dict[str, Any]:
        """
        Refresh the authentication token.
        
        Returns:
            Dictionary containing refresh response
            
        Raises:
            APICAuthenticationError: If token refresh fails
        """
        if not self.token:
            raise APICAuthenticationError("No active token to refresh")
        
        refresh_url = f"{self.apic_url}/api/aaaRefresh.json"
        
        try:
            logger.info("Refreshing APIC authentication token")
            
            response = self.session.get(
                refresh_url,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            refresh_data = response.json()
            
            # Parse refresh response
            imdata = refresh_data.get('imdata', [])
            if imdata and 'aaaLogin' in imdata[0]:
                login_attrs = imdata[0]['aaaLogin']['attributes']
                
                # Update token details
                self.token = login_attrs.get('token')
                refresh_timeout = int(login_attrs.get('refreshTimeoutSeconds', 28800))
                self.token_expiry = datetime.now() + timedelta(seconds=refresh_timeout)
                
                # Update session headers
                self.session.headers.update({'APIC-challenge': self.token})
                
                logger.info(f"Token successfully refreshed, expires at: {self.token_expiry}")
                
                return {
                    "status": "success",
                    "message": "Token successfully refreshed",
                    "token_expiry": self.token_expiry.isoformat()
                }
            else:
                raise APICAuthenticationError("Invalid refresh response format")
                
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise APICAuthenticationError(f"Token refresh failed: {str(e)}")
    
    def make_authenticated_request(self, endpoint: str, method: str = 'GET', 
                                 data: Optional[Union[Dict, str]] = None,
                                 params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Make an authenticated API request to the APIC.
        
        Args:
            endpoint: API endpoint (e.g., '/api/class/fvTenant.json')
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload for POST/PUT requests
            params: Query parameters
            
        Returns:
            JSON response from APIC
            
        Raises:
            APICAuthenticationError: If request fails or authentication is invalid
        """
        # Check if we need to authenticate or refresh token
        if not self.is_authenticated():
            if self.token:
                # Try to refresh first
                try:
                    self.refresh_token()
                except APICAuthenticationError:
                    # Refresh failed, re-authenticate
                    self.authenticate()
            else:
                # No token, authenticate
                self.authenticate()
        
        # Construct full URL
        url = f"{self.apic_url}{endpoint}"
        
        try:
            # Prepare request arguments
            request_kwargs = {
                'verify': self.verify_ssl,
                'timeout': self.timeout,
                'params': params
            }
            
            # Add data for POST/PUT requests
            if data is not None:
                if isinstance(data, dict):
                    request_kwargs['json'] = data
                else:
                    request_kwargs['data'] = data
            
            # Make the request
            response = self.session.request(method, url, **request_kwargs)
            response.raise_for_status()
            
            # Parse JSON response
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                # Authentication expired, try once more
                logger.warning("Received 401, re-authenticating...")
                self.authenticate()
                response = self.session.request(method, url, **request_kwargs)
                response.raise_for_status()
                return response.json()
            else:
                raise APICAuthenticationError(f"HTTP error {e.response.status_code}: {e.response.text}")
                
        except Exception as e:
            raise APICAuthenticationError(f"Request failed: {str(e)}")
    
    def logout(self) -> bool:
        """
        Logout from the APIC and invalidate the current session.
        
        Returns:
            True if logout successful, False otherwise
        """
        if not self.token:
            logger.info("No active session to logout")
            return True
        
        logout_url = f"{self.apic_url}/api/aaaLogout.json"
        
        try:
            logger.info("Logging out from APIC")
            
            response = self.session.post(
                logout_url,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            # Clear authentication state regardless of response
            self.token = None
            self.session_id = None
            self.token_expiry = None
            self.user_domain = None
            
            # Clear session headers
            if 'APIC-challenge' in self.session.headers:
                del self.session.headers['APIC-challenge']
            
            if response.status_code == 200:
                logger.info("Successfully logged out from APIC")
                return True
            else:
                logger.warning(f"Logout response: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            # Still clear local state even if logout request failed
            self.token = None
            self.session_id = None
            self.token_expiry = None
            self.user_domain = None
            return False
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get current session information.
        
        Returns:
            Dictionary containing session details
        """
        return {
            "apic_url": self.apic_url,
            "username": self.username,
            "authenticated": self.is_authenticated(),
            "token_present": bool(self.token),
            "token_expiry": self.token_expiry.isoformat() if self.token_expiry else None,
            "session_id": self.session_id,
            "user_domain": self.user_domain,
            "apic_version": self.apic_version,
            "apic_build_time": self.apic_build_time,
            "apic_node": self.apic_node,
            "verify_ssl": self.verify_ssl,
            "timeout": self.timeout
        }
    
    def __del__(self):
        """Cleanup: attempt to logout when object is destroyed."""
        if hasattr(self, 'token') and self.token:
            try:
                self.logout()
            except:
                pass  # Ignore errors during cleanup


# Convenience functions for backward compatibility and ease of use

def create_authenticator(apic_url: Optional[str] = None, verify_ssl: Optional[bool] = None) -> APICAuthenticator:
    """
    Create and return an APICAuthenticator instance.
    
    Args:
        apic_url: APIC controller URL (optional)
        verify_ssl: Whether to verify SSL certificates (optional)
        
    Returns:
        APICAuthenticator instance
    """
    return APICAuthenticator(apic_url=apic_url, verify_ssl=verify_ssl)


def authenticate_to_apic(apic_url: Optional[str] = None, username: Optional[str] = None, 
                        password: Optional[str] = None, verify_ssl: Optional[bool] = None) -> APICAuthenticator:
    """
    Convenience function to create and authenticate an APIC connection.
    
    Args:
        apic_url: APIC controller URL (optional, uses env var)
        username: APIC username (optional, uses env var)
        password: APIC password (optional, uses env var)
        verify_ssl: Whether to verify SSL certificates (optional, uses env var)
        
    Returns:
        Authenticated APICAuthenticator instance
        
    Raises:
        APICAuthenticationError: If authentication fails
    """
    authenticator = APICAuthenticator(apic_url=apic_url, verify_ssl=verify_ssl)
    authenticator.authenticate(username=username, password=password)
    return authenticator


if __name__ == "__main__":
    """
    Example usage and testing functionality.
    """
    import sys
    
    # Configure logging for testing
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        # Test authentication
        print("Testing APIC Authentication...")
        authenticator = create_authenticator()
        
        result = authenticator.authenticate()
        print(f"Authentication Result: {result}")
        
        # Test session info
        session_info = authenticator.get_session_info()
        print(f"Session Info: {json.dumps(session_info, indent=2, default=str)}")
        
        # Test a simple API call
        try:
            response = authenticator.make_authenticated_request('/api/class/aaaUser.json?query-target-self')
            print(f"API Test successful: {len(response.get('imdata', []))} user objects returned")
        except Exception as e:
            print(f"API Test failed: {e}")
        
        # Logout
        logout_result = authenticator.logout()
        print(f"Logout successful: {logout_result}")
        
    except APICAuthenticationError as e:
        print(f"Authentication Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected Error: {e}")
        sys.exit(1)
