"""GuardDuty Service Wrapper for AWS Security MCP.

This wrapper consolidates GuardDuty operations into a single tool while maintaining
semantic richness through detailed operation descriptions.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from aws_security_mcp.tools import register_tool

# Import existing GuardDuty functions to reuse them
from aws_security_mcp.tools.guardduty_tools import (
    list_detectors as _list_detectors,
    list_findings as _list_findings,
    get_finding_details as _get_finding_details,
    list_ip_sets as _list_ip_sets,
    list_threat_intel_sets as _list_threat_intel_sets
)

logger = logging.getLogger(__name__)

@register_tool()
async def guardduty_security_operations(operation: str, session_context: Optional[str] = None, **params) -> str:
    """GuardDuty Security Operations Hub - Comprehensive threat detection and monitoring.
    
    🔍 DETECTOR MANAGEMENT:
    - list_detectors: List all GuardDuty detectors in account with status and configuration
    
    🚨 FINDINGS & THREATS:
    - list_findings: Get security findings with advanced filtering (severity, search terms)
    - get_finding_details: Deep analysis of specific findings with remediation guidance
    
    🛡️ THREAT INTELLIGENCE:
    - list_ip_sets: View trusted/threat IP sets for custom threat detection
    - list_threat_intel_sets: Manage threat intelligence feeds and indicators
    
    💡 INTELLIGENT USAGE EXAMPLES:
    
    🔍 Find all detectors:
    operation="list_detectors"
    
    🔍 Find detectors across accounts:
    operation="list_detectors", session_context="123456789012_aws_dev"
    
    🚨 Get high-severity threats:
    operation="list_findings", detector_id="abc123", severity="HIGH", max_results=50
    
    🔎 Search for specific threats:
    operation="list_findings", detector_id="abc123", search_term="cryptocurrency"
    
    📊 Analyze specific finding:
    operation="get_finding_details", detector_id="abc123", finding_id="def456"
    
    🛡️ Review IP threat intelligence:
    operation="list_ip_sets", detector_id="abc123"
    
    🔄 Cross-account access example:
    operation="list_findings", detector_id="abc123", session_context="123456789012_aws_dev"
    
    Args:
        operation: The security operation to perform (see descriptions above)
        session_context: Optional session key for cross-account access (e.g., "123456789012_aws_dev")
        detector_id: GuardDuty detector ID (required for most operations)
        max_results: Maximum number of results to return (default: 50-100)
        severity: Filter findings by severity (LOW, MEDIUM, HIGH, ALL)
        search_term: Text search across finding details
        finding_id: Specific finding ID for detailed analysis
        finding_ids: List of specific finding IDs to retrieve
        
    Returns:
        JSON formatted response with operation results and security insights
    """
    
    logger.info(f"GuardDuty operation requested: {operation} (session_context={session_context})")
    
    # Handle nested params object from Claude Desktop
    if "params" in params and isinstance(params["params"], dict):
        params = params["params"]
    
    try:
        if operation == "list_detectors":
            max_results = params.get("max_results", 100)
            return await _list_detectors(max_results=max_results, session_context=session_context)
            
        elif operation == "list_findings":
            # Ensure detector_id is provided
            if "detector_id" not in params:
                return json.dumps({
                    "error": "detector_id is required for list_findings operation",
                    "usage": "operation='list_findings', detector_id='your-detector-id'"
                })
            
            # Extract parameters with defaults
            detector_id = params["detector_id"]
            max_results = params.get("max_results", 50)
            finding_ids = params.get("finding_ids")
            severity = params.get("severity")
            search_term = params.get("search_term")
            
            return await _list_findings(
                detector_id=detector_id,
                max_results=max_results,
                finding_ids=finding_ids,
                severity=severity,
                search_term=search_term,
                session_context=session_context
            )
            
        elif operation == "get_finding_details":
            # Ensure required parameters are provided
            required_params = ["detector_id", "finding_id"]
            missing_params = [param for param in required_params if param not in params]
            
            if missing_params:
                return json.dumps({
                    "error": f"Missing required parameters: {missing_params}",
                    "usage": "operation='get_finding_details', detector_id='detector-id', finding_id='finding-id'"
                })
            
            detector_id = params["detector_id"]
            finding_id = params["finding_id"]
            
            return await _get_finding_details(
                detector_id=detector_id,
                finding_id=finding_id,
                session_context=session_context
            )
            
        elif operation == "list_ip_sets":
            if "detector_id" not in params:
                return json.dumps({
                    "error": "detector_id is required for list_ip_sets operation",
                    "usage": "operation='list_ip_sets', detector_id='your-detector-id'"
                })
            
            detector_id = params["detector_id"]
            max_results = params.get("max_results", 50)
            
            return await _list_ip_sets(
                detector_id=detector_id,
                max_results=max_results,
                session_context=session_context
            )
            
        elif operation == "list_threat_intel_sets":
            if "detector_id" not in params:
                return json.dumps({
                    "error": "detector_id is required for list_threat_intel_sets operation",
                    "usage": "operation='list_threat_intel_sets', detector_id='your-detector-id'"
                })
            
            detector_id = params["detector_id"]
            max_results = params.get("max_results", 50)
            
            return await _list_threat_intel_sets(
                detector_id=detector_id,
                max_results=max_results,
                session_context=session_context
            )
            
        else:
            # Provide helpful error with available operations
            available_operations = [
                "list_detectors",
                "list_findings", 
                "get_finding_details",
                "list_ip_sets",
                "list_threat_intel_sets"
            ]
            
            return json.dumps({
                "error": f"Unknown operation: {operation}",
                "available_operations": available_operations,
                "usage_examples": {
                    "list_detectors": "operation='list_detectors'",
                    "list_findings": "operation='list_findings', detector_id='detector-id', severity='HIGH'",
                    "get_finding_details": "operation='get_finding_details', detector_id='detector-id', finding_id='finding-id'"
                }
            })
            
    except Exception as e:
        logger.error(f"Error in GuardDuty operation '{operation}': {e}")
        return json.dumps({
            "error": {
                "message": f"Error executing GuardDuty operation '{operation}': {str(e)}",
                "type": type(e).__name__,
                "operation": operation,
                "parameters": params
            }
        })

@register_tool() 
async def discover_guardduty_operations() -> str:
    """Discover all available GuardDuty security operations with detailed usage examples.
    
    This tool provides comprehensive documentation of GuardDuty operations available
    through the guardduty_security_operations tool, including parameter requirements
    and practical usage examples.
    
    Returns:
        Detailed catalog of GuardDuty operations with examples and parameter descriptions
    """
    
    operations_catalog = {
        "service": "AWS GuardDuty",
        "description": "Threat detection and continuous security monitoring service",
        "wrapper_tool": "guardduty_security_operations",
        "cross_account_support": {
            "enabled": True,
            "parameter": "session_context",
            "format": "123456789012_aws_dev",
            "description": "Access GuardDuty resources across different AWS accounts"
        },
        "operations": {
            "list_detectors": {
                "description": "List all GuardDuty detectors in the AWS account",
                "parameters": {
                    "max_results": {"type": "int", "default": 100, "description": "Maximum detectors to return"},
                    "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                },
                "examples": [
                    "guardduty_security_operations(operation='list_detectors')",
                    "guardduty_security_operations(operation='list_detectors', session_context='123456789012_aws_dev')"
                ],
                "use_cases": [
                    "Check if GuardDuty is enabled",
                    "Audit detector configurations",
                    "Get detector IDs for other operations",
                    "Cross-account detector discovery"
                ]
            },
            "list_findings": {
                "description": "Retrieve security findings with advanced filtering capabilities", 
                "parameters": {
                    "detector_id": {"type": "str", "required": True, "description": "GuardDuty detector ID"},
                    "max_results": {"type": "int", "default": 50, "description": "Maximum findings to return"},
                    "severity": {"type": "str", "options": ["LOW", "MEDIUM", "HIGH", "ALL"], "description": "Filter by severity"},
                    "search_term": {"type": "str", "description": "Text search across finding details"},
                    "finding_ids": {"type": "list", "description": "Specific finding IDs to retrieve"},
                    "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                },
                "examples": [
                    "guardduty_security_operations(operation='list_findings', detector_id='abc123')",
                    "guardduty_security_operations(operation='list_findings', detector_id='abc123', severity='HIGH')",
                    "guardduty_security_operations(operation='list_findings', detector_id='abc123', search_term='cryptocurrency')",
                    "guardduty_security_operations(operation='list_findings', detector_id='abc123', session_context='123456789012_aws_dev')"
                ],
                "use_cases": [
                    "Monitor active security threats",
                    "Filter findings by severity level", 
                    "Search for specific threat patterns",
                    "Export findings for reporting",
                    "Cross-account threat monitoring"
                ]
            },
            "get_finding_details": {
                "description": "Get comprehensive details about a specific security finding",
                "parameters": {
                    "detector_id": {"type": "str", "required": True, "description": "GuardDuty detector ID"},
                    "finding_id": {"type": "str", "required": True, "description": "Specific finding ID to analyze"},
                    "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                },
                "examples": [
                    "guardduty_security_operations(operation='get_finding_details', detector_id='abc123', finding_id='def456')",
                    "guardduty_security_operations(operation='get_finding_details', detector_id='abc123', finding_id='def456', session_context='123456789012_aws_dev')"
                ],
                "use_cases": [
                    "Investigate specific security incidents",
                    "Get remediation recommendations",
                    "Analyze attack patterns and IOCs",
                    "Cross-account incident investigation"
                ]
            },
            "list_ip_sets": {
                "description": "List trusted and threat IP sets configured in GuardDuty",
                "parameters": {
                    "detector_id": {"type": "str", "required": True, "description": "GuardDuty detector ID"},
                    "max_results": {"type": "int", "default": 50, "description": "Maximum IP sets to return"},
                    "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                },
                "examples": [
                    "guardduty_security_operations(operation='list_ip_sets', detector_id='abc123')",
                    "guardduty_security_operations(operation='list_ip_sets', detector_id='abc123', session_context='123456789012_aws_dev')"
                ],
                "use_cases": [
                    "Review custom threat intelligence",
                    "Audit trusted IP configurations",
                    "Manage IP-based detection rules",
                    "Cross-account IP set management"
                ]
            },
            "list_threat_intel_sets": {
                "description": "List threat intelligence feeds and indicators",
                "parameters": {
                    "detector_id": {"type": "str", "required": True, "description": "GuardDuty detector ID"},
                    "max_results": {"type": "int", "default": 50, "description": "Maximum threat intel sets to return"},
                    "session_context": {"type": "str", "description": "Optional session key for cross-account access"}
                },
                "examples": [
                    "guardduty_security_operations(operation='list_threat_intel_sets', detector_id='abc123')",
                    "guardduty_security_operations(operation='list_threat_intel_sets', detector_id='abc123', session_context='123456789012_aws_dev')"
                ],
                "use_cases": [
                    "Review threat intelligence sources",
                    "Validate threat feed configurations",
                    "Audit custom threat indicators",
                    "Cross-account threat intelligence management"
                ]
            }
        },
        "security_insights": {
            "best_practices": [
                "Always start with list_detectors to get detector IDs",
                "Use severity filtering for high-priority threat triage",
                "Regular monitoring of HIGH severity findings",
                "Review threat intelligence configurations periodically",
                "Implement cross-account monitoring for centralized security"
            ],
            "common_workflows": [
                "1. List detectors → 2. List high-severity findings → 3. Analyze specific findings",
                "1. List detectors → 2. Review IP sets → 3. Validate threat intelligence",
                "Cross-account: 1. List detectors with session_context → 2. Monitor findings across accounts"
            ]
        }
    }
    
    return json.dumps(operations_catalog, indent=2) 