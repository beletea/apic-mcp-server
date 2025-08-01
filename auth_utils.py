#!/usr/bin/env python3
"""
Cisco ACI APIC Authentication Utility

This module provides authentication utilities for connecting to Cisco ACI APIC controllers.
It handles JWT token-based authentication, session management, and API request functionality.
All configuration is read from environment variables for security and flexibility.
"""
import os
import json
import httpx
import logging
from typing import Dict, Any, Optional, Union
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class APICAuthenticationError(Exception):
    """Custom exception for APIC authentication errors."""
    pass

class APICAuthenticator:
    """
    Cisco ACI APIC Authentication and Session Management Class.
    Handles authentication to Cisco ACI APIC controllers using username/password and JWT token management.
    """
    def __init__(self, apic_url: Optional[str] = None, verify_ssl: Optional[bool] = None, timeout: Optional[int] = None):
        self.apic_url = apic_url or os.getenv('APIC_URL')
        self.verify_ssl = verify_ssl if verify_ssl is not None else os.getenv('APIC_VERIFY_SSL', 'false').lower() == 'true'
        self.timeout = timeout or int(os.getenv('APIC_TIMEOUT', '30'))
        self.username = os.getenv('APIC_USERNAME')
        self.password = os.getenv('APIC_PASSWORD')
        self.client = httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout, follow_redirects=False)
        # Authentication state
        self.token = None
        self.session_id = None
        self.token_expiry = None
        self.user_domain = None
        self.apic_version = None
        self.apic_build_time = None
        self.apic_node = None

    async def authenticate(self, username: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Authenticate to the APIC controller and obtain a JWT token.
        Returns a dictionary containing authentication response and session information.
        Raises APICAuthenticationError if authentication fails.
        """
        auth_username = username or self.username
        auth_password = password or self.password
        auth_payload = {
            "aaaUser": {
                "attributes": {
                    "name": auth_username,
                    "pwd": auth_password
                }
            }
        }
        auth_url = f"{self.apic_url}/api/aaaLogin.json"
        try:
            response = await self.client.post(auth_url, json=auth_payload)
            response.raise_for_status()
            auth_data = response.json()
            imdata = auth_data.get('imdata', [])
            if not imdata:
                raise APICAuthenticationError("No authentication data in response")
            auth_info = imdata[0]
            if 'aaaLogin' not in auth_info:
                if 'error' in auth_info:
                    error_attrs = auth_info['error']['attributes']
                    error_msg = error_attrs.get('text', 'Unknown authentication error')
                    raise APICAuthenticationError(f"Authentication failed: {error_msg}")
                else:
                    raise APICAuthenticationError("Unexpected response format")
            login_attrs = auth_info['aaaLogin']['attributes']
            self.token = login_attrs.get('token')
            self.session_id = login_attrs.get('urlToken') or login_attrs.get('sessionId')
            self.user_domain = login_attrs.get('userDomain', '')
            self.apic_version = login_attrs.get('version', 'Unknown')
            self.apic_build_time = login_attrs.get('buildTime', 'Unknown')
            self.apic_node = login_attrs.get('node', 'Unknown')
            refresh_timeout = int(login_attrs.get('refreshTimeoutSeconds', 28800))
            self.token_expiry = datetime.now() + timedelta(seconds=refresh_timeout)
            self.client.headers.update({
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
        except httpx.RequestError as e:
            error_msg = f"Network error: {str(e)}"
            logger.error(error_msg)
            raise APICAuthenticationError(f"Authentication failed: {error_msg}")
        except httpx.HTTPStatusError as e:
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
        """
        if not self.token or not self.token_expiry:
            return False
        buffer_time = timedelta(minutes=5)
        return datetime.now() < (self.token_expiry - buffer_time)

    async def refresh_token(self) -> Dict[str, Any]:
        """
        Refresh the authentication token.
        """
        if not self.token:
            raise APICAuthenticationError("No active token to refresh")
        refresh_url = f"{self.apic_url}/api/aaaRefresh.json"
        try:
            logger.info("Refreshing APIC authentication token")
            response = await self.client.get(refresh_url)
            response.raise_for_status()
            refresh_data = response.json()
            imdata = refresh_data.get('imdata', [])
            if imdata and 'aaaLogin' in imdata[0]:
                login_attrs = imdata[0]['aaaLogin']['attributes']
                self.token = login_attrs.get('token')
                self.session_id = login_attrs.get('urlToken') or login_attrs.get('sessionId')
                self.user_domain = login_attrs.get('userDomain', '')
                refresh_timeout = int(login_attrs.get('refreshTimeoutSeconds', 28800))
                self.token_expiry = datetime.now() + timedelta(seconds=refresh_timeout)
                self.client.headers.update({'APIC-challenge': self.token})
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

    async def make_authenticated_request(self, endpoint: str, method: str = 'GET', data: Optional[Union[Dict, str]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make an authenticated API request to the APIC.
        """
        if not self.is_authenticated():
            if self.token:
                try:
                    await self.refresh_token()
                except APICAuthenticationError:
                    await self.authenticate()
            else:
                await self.authenticate()
        url = f"{self.apic_url}{endpoint}"
        try:
            request_kwargs = {
                'headers': self.client.headers,
                'params': params,
                'timeout': self.timeout
            }
            if data is not None:
                if isinstance(data, dict):
                    request_kwargs['json'] = data
                else:
                    request_kwargs['data'] = data
            response = await self.client.request(method, url, **request_kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.warning("Received 401, re-authenticating...")
                await self.authenticate()
                response = await self.client.request(method, url, **request_kwargs)
                response.raise_for_status()
                return response.json()
            else:
                raise APICAuthenticationError(f"HTTP error {e.response.status_code}: {e.response.text}")
        except Exception as e:
            raise APICAuthenticationError(f"Request failed: {str(e)}")

    async def logout(self) -> bool:
        """
        Logout from the APIC and invalidate the current session.
        """
        if not self.token:
            logger.info("No active session to logout")
            return True
        logout_url = f"{self.apic_url}/api/aaaLogout.json"
        try:
            logger.info("Logging out from APIC")
            response = await self.client.post(logout_url)
            self.token = None
            self.session_id = None
            self.token_expiry = None
            self.user_domain = None
            if 'APIC-challenge' in self.client.headers:
                del self.client.headers['APIC-challenge']
            if response.status_code == 200:
                logger.info("Successfully logged out from APIC")
                return True
            else:
                logger.warning(f"Logout response: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return False
