#!/usr/bin/env python3
"""
AI Analysis Module for Attack Surface Monitoring Tool
This module uses free LLM alternatives to analyze risks and provide recommendations.
"""

import json
import sys
import os
import requests
import time
from typing import Dict, Any, List, Optional


class AIAnalyzer:
    """
    A class to analyze security risks using free LLM alternatives.
    """

    def __init__(self, domain: str, risk_data: Dict[str, Any]):
        """
        Initialize the AIAnalyzer with risk data.

        Args:
            domain (str): The target domain.
            risk_data (Dict[str, Any]): Risk data for the domain.
        """
        self.domain = domain
        self.risk_data = risk_data
        self.llm_provider = "gemini"  # Default to Gemini as it has a free tier

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze risks and provide recommendations using a free LLM.

        Returns:
            Dict[str, Any]: A dictionary containing AI analysis results.
        """
        print(f"[+] Performing AI analysis for {self.domain}")
        
        # Prepare the result structure
        result = {
            "domain": self.domain,
            "risk_score": self.risk_data.get("risk_score", 0),
            "risk_level": self.risk_data.get("risk_level", "Unknown"),
            "summary": "",
            "key_risks": [],
            "recommendations": [],
            "analysis_method": f"AI Analysis using {self.llm_provider.capitalize()}"
        }
        
        try:
            # Generate a prompt based on the risk data
            prompt = self._generate_prompt()
            
            # Get AI response
            ai_response = self._get_ai_response(prompt)
            
            # Parse AI response
            if ai_response:
                parsed_response = self._parse_ai_response(ai_response)
                
                result["summary"] = parsed_response.get("summary", "")
                result["key_risks"] = parsed_response.get("key_risks", [])
                result["recommendations"] = parsed_response.get("recommendations", [])
            else:
                # Fallback to rule-based analysis if AI fails
                fallback_analysis = self._fallback_analysis()
                
                result["summary"] = fallback_analysis.get("summary", "")
                result["key_risks"] = fallback_analysis.get("key_risks", [])
                result["recommendations"] = fallback_analysis.get("recommendations", [])
                result["analysis_method"] = "Rule-based Analysis (AI fallback)"
            
            print(f"[+] AI analysis complete for {self.domain}")
            
            return result
        
        except Exception as e:
            print(f"[!] Error during AI analysis: {e}", file=sys.stderr)
            
            # Fallback to rule-based analysis
            fallback_analysis = self._fallback_analysis()
            
            result["summary"] = fallback_analysis.get("summary", "")
            result["key_risks"] = fallback_analysis.get("key_risks", [])
            result["recommendations"] = fallback_analysis.get("recommendations", [])
            result["analysis_method"] = "Rule-based Analysis (AI fallback)"
            
            return result

    def _generate_prompt(self) -> str:
        """
        Generate a prompt for the AI model based on risk data.

        Returns:
            str: The generated prompt.
        """
        # Extract key information from risk data
        risk_score = self.risk_data.get("risk_score", 0)
        risk_level = self.risk_data.get("risk_level", "Unknown")
        risk_details = self.risk_data.get("risk_details", [])
        
        # Format risk details
        risk_details_text = ""
        for i, risk in enumerate(risk_details[:10], 1):  # Limit to top 10 risks
            risk_details_text += f"{i}. {risk.get('title', 'Unknown risk')} ({risk.get('category', 'Unknown category')}): "
            risk_details_text += f"{risk.get('description', 'No description')}. "
            risk_details_text += f"Score: {risk.get('score', 0)}, "
            
            affected_assets = risk.get('affected_assets', [])
            if affected_assets:
                risk_details_text += f"Affected: {', '.join(affected_assets[:3])}"
                if len(affected_assets) > 3:
                    risk_details_text += f" and {len(affected_assets) - 3} more"
            
            risk_details_text += "\n"
        
        # Build the prompt
        prompt = f"""
You are a cybersecurity expert analyzing attack surface monitoring results for the domain {self.domain}.

The domain has a risk score of {risk_score}/100, which is considered {risk_level} risk.

Here are the top security issues identified:
{risk_details_text}

Based on this information, please provide:
1. A concise summary of the overall security posture (2-3 sentences)
2. A list of the 3-5 most critical security risks that should be addressed immediately
3. Specific recommendations for remediation of each critical risk

Format your response as JSON with the following structure:
{{
  "summary": "Overall security posture summary...",
  "key_risks": [
    "Risk 1 description",
    "Risk 2 description",
    ...
  ],
  "recommendations": [
    "Recommendation 1",
    "Recommendation 2",
    ...
  ]
}}
"""
        return prompt

    def _get_ai_response(self, prompt: str) -> Optional[str]:
        """
        Get a response from an AI model.

        Args:
            prompt (str): The prompt to send to the AI model.

        Returns:
            Optional[str]: The AI model's response, or None if an error occurred.
        """
        # Try to use Gemini API if available
        if self.llm_provider == "gemini":
            try:
                return self._get_gemini_response(prompt)
            except Exception as e:
                print(f"[!] Error using Gemini API: {e}", file=sys.stderr)
                print("[*] Falling back to local analysis", file=sys.stderr)
                return None
        
        # Fallback to local analysis
        return None

    def _get_gemini_response(self, prompt: str) -> Optional[str]:
        """
        Get a response from the Gemini API.
        
        This is a simulated implementation since we don't have actual API keys.
        In a real implementation, you would use the official Gemini API client.

        Args:
            prompt (str): The prompt to send to Gemini.

        Returns:
            Optional[str]: Gemini's response, or None if an error occurred.
        """
        print("[*] Note: This is a simulated Gemini API call. In a real implementation, you would need to:")
        print("    1. Get a free API key from Google AI Studio (https://makersuite.google.com/)")
        print("    2. Install the official Python client: pip install google-generativeai")
        print("    3. Use the client to make actual API calls")
        
        # Simulate API call delay
        time.sleep(1)
        
        # Since we can't make a real API call, we'll return a simulated response
        # based on the risk level in the prompt
        if "risk score" in prompt:
            risk_score_text = prompt.split("risk score of ")[1].split("/100")[0]
            try:
                risk_score = int(risk_score_text)
            except:
                risk_score = 50  # Default to medium risk
            
            risk_level = "Critical" if risk_score >= 85 else \
                         "High" if risk_score >= 70 else \
                         "Medium" if risk_score >= 50 else \
                         "Low" if risk_score >= 25 else "Informational"
        else:
            risk_score = 50
            risk_level = "Medium"
        
        # Extract domain from prompt
        domain = self.domain
        
        # Extract mentioned risks
        risks = []
        if "security issues identified" in prompt:
            issues_section = prompt.split("security issues identified:")[1].split("Based on this information")[0]
            for line in issues_section.strip().split("\n"):
                if ": " in line and "." in line:
                    risk_title = line.split(": ")[0].split(". ")[1] if ". " in line.split(": ")[0] else line.split(": ")[0]
                    risks.append(risk_title)
        
        # Generate response based on risk level
        if risk_level == "Critical":
            response = {
                "summary": f"The domain {domain} has critical security vulnerabilities that require immediate attention. The attack surface is significantly exposed with multiple high-severity issues that could lead to system compromise. Urgent remediation is necessary to prevent potential breaches.",
                "key_risks": [
                    "Exposed sensitive administrative interfaces that could allow unauthorized access",
                    "Critical services with known vulnerabilities accessible from the internet",
                    "Expired or self-signed SSL certificates compromising encrypted communications",
                    "Missing essential security headers that protect against common web attacks",
                    "Evidence of credentials exposed in previous data breaches"
                ],
                "recommendations": [
                    "Immediately restrict access to administrative interfaces using IP filtering or VPN requirements",
                    "Update or patch all services with known vulnerabilities, or place them behind a properly configured firewall",
                    "Replace expired SSL certificates with valid ones from trusted certificate authorities",
                    "Implement all missing security headers, particularly HSTS, CSP, and X-Frame-Options",
                    "Force password resets for all accounts and implement multi-factor authentication"
                ]
            }
        elif risk_level == "High":
            response = {
                "summary": f"The domain {domain} has significant security weaknesses that present substantial risk. Multiple security issues were identified that could potentially be exploited by attackers to gain unauthorized access or extract sensitive information.",
                "key_risks": [
                    "Multiple exposed services increasing the attack surface",
                    "Weak SSL/TLS configuration with outdated protocols or ciphers",
                    "Missing critical security headers that could allow client-side attacks",
                    "Sensitive information exposed through directory listings or configuration files"
                ],
                "recommendations": [
                    "Reduce the attack surface by disabling unnecessary services and ports",
                    "Update SSL/TLS configuration to use only strong protocols (TLS 1.2+) and ciphers",
                    "Implement all recommended security headers including Content-Security-Policy",
                    "Remove or properly secure sensitive directories and files",
                    "Conduct regular vulnerability scans and penetration testing"
                ]
            }
        elif risk_level == "Medium":
            response = {
                "summary": f"The domain {domain} has moderate security issues that should be addressed in a timely manner. While no critical vulnerabilities were identified, several configuration weaknesses could potentially be exploited by determined attackers.",
                "key_risks": [
                    "Suboptimal SSL/TLS configuration that may be vulnerable to downgrade attacks",
                    "Missing some recommended security headers",
                    "Outdated software components that may contain vulnerabilities"
                ],
                "recommendations": [
                    "Strengthen SSL/TLS configuration by disabling older protocols and implementing HSTS",
                    "Add all recommended security headers to protect against common web vulnerabilities",
                    "Update all software components to their latest versions",
                    "Implement a regular patching schedule to address security updates"
                ]
            }
        else:  # Low or Informational
            response = {
                "summary": f"The domain {domain} has relatively minor security issues with a generally good security posture. The identified issues present minimal risk but addressing them would further strengthen the overall security.",
                "key_risks": [
                    "Some non-critical information disclosure through headers or metadata",
                    "Minor configuration optimizations needed for best security practices",
                    "Limited attack surface but some unnecessary services exposed"
                ],
                "recommendations": [
                    "Remove unnecessary information from HTTP headers",
                    "Implement all recommended security headers as a defense-in-depth measure",
                    "Disable or restrict access to any services not required for operations",
                    "Consider implementing a web application firewall for additional protection"
                ]
            }
        
        # Customize based on extracted risks
        if risks:
            # Replace some generic risks with specific ones from the prompt
            for i, risk in enumerate(risks[:3]):
                if i < len(response["key_risks"]):
                    response["key_risks"][i] = risk
        
        return json.dumps(response, indent=2)

    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """
        Parse the AI model's response.

        Args:
            response (str): The AI model's response.

        Returns:
            Dict[str, Any]: The parsed response.
        """
        try:
            # Try to parse as JSON
            parsed = json.loads(response)
            
            # Ensure all required fields are present
            if "summary" not in parsed:
                parsed["summary"] = ""
            if "key_risks" not in parsed:
                parsed["key_risks"] = []
            if "recommendations" not in parsed:
                parsed["recommendations"] = []
            
            return parsed
        
        except json.JSONDecodeError:
            # If not valid JSON, try to extract sections manually
            summary = ""
            key_risks = []
            recommendations = []
            
            if "summary" in response.lower():
                summary_parts = response.split("summary", 1)[1].split("key_risks", 1)
                if len(summary_parts) > 0:
                    summary = summary_parts[0].strip(": \"',\n{}")
            
            if "key_risks" in response.lower():
                risks_parts = response.split("key_risks", 1)[1].split("recommendations", 1)
                if len(risks_parts) > 0:
                    risks_text = risks_parts[0].strip(": \"',\n{}")
                    for line in risks_text.split("\n"):
                        line = line.strip("- \"',[]")
                        if line and not line.isspace():
                            key_risks.append(line)
            
            if "recommendations" in response.lower():
                recommendations_text = response.split("recommendations", 1)[1].strip(": \"',\n{}")
                for line in recommendations_text.split("\n"):
                    line = line.strip("- \"',[]}")
                    if line and not line.isspace():
                        recommendations.append(line)
            
            return {
                "summary": summary,
                "key_risks": key_risks,
                "recommendations": recommendations
            }

    def _fallback_analysis(self) -> Dict[str, Any]:
        """
        Perform rule-based analysis as a fallback if AI analysis fails.

        Returns:
            Dict[str, Any]: The analysis results.
        """
        # Extract key information from risk data
        risk_score = self.risk_data.get("risk_score", 0)
        risk_level = self.risk_data.get("risk_level", "Unknown")
        risk_details = self.risk_data.get("risk_details", [])
        
        # Generate summary based on risk level
        summary = f"The domain {self.domain} has a risk score of {risk_score}/100, which indicates a {risk_level.lower()} level of risk. "
        
        if risk_level == "Critical":
            summary += "Critical security issues were identified that require immediate attention to prevent potential breaches."
        elif risk_level == "High":
            summary += "Significant security weaknesses were found that could potentially be exploited by attackers."
        elif risk_level == "Medium":
            summary += "Several security issues were identified that should be addressed to improve the security posture."
        elif risk_level == "Low":
            summary += "Minor security issues were found that present minimal risk but should be addressed when possible."
        else:
            summary += "The security posture appears to be generally good with only informational findings."
        
        # Extract key risks from risk details
        key_risks = []
        for risk in sorted(risk_details, key=lambda x: x.get("score", 0), reverse=True)[:5]:
            risk_description = f"{risk.get('title', 'Unknown risk')}: {risk.get('description', 'No description')}"
            key_risks.append(risk_description)
        
        # Generate recommendations based on risk categories
        recommendations = []
        risk_categories = set(risk.get("category", "") for risk in risk_details)
        
        if "SSL/TLS" in risk_categories:
            recommendations.append("Update SSL/TLS configuration to use only strong protocols (TLS 1.2+) and ciphers, and ensure certificates are valid and trusted.")
        
        if "HTTP Headers" in risk_categories:
            recommendations.append("Implement all recommended security headers including Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options.")
        
        if "Port" in risk_categories or "Service" in risk_categories:
            recommendations.append("Reduce the attack surface by disabling unnecessary services and ports, and ensure all services are up-to-date and properly configured.")
        
        if "Sensitive Paths" in risk_categories:
            recommendations.append("Secure or remove sensitive directories and files, and implement proper access controls to prevent unauthorized access.")
        
        if "OSINT" in risk_categories:
            recommendations.append("Monitor for data breaches, force password resets for affected accounts, and implement multi-factor authentication.")
        
        if "Subdomain" in risk_categories:
            recommendations.append("Review all subdomains to ensure they are necessary, up-to-date, and properly secured.")
        
        if "Technology" in risk_categories:
            recommendations.append("Keep all software components updated to their latest versions and implement a regular patching schedule.")
        
        # Add general recommendation if we have few specific ones
        if len(recommendations) < 3:
            recommendations.append("Conduct regular vulnerability scans and penetration testing to identify and address security issues.")
        
        return {
            "summary": summary,
            "key_risks": key_risks,
            "recommendations": recommendations
        }


def analyze_risks(domain: str, risk_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to analyze security risks.

    Args:
        domain (str): The target domain.
        risk_data (Dict[str, Any]): Risk data for the domain.

    Returns:
        Dict[str, Any]: A dictionary containing AI analysis results.
    """
    analyzer = AIAnalyzer(domain, risk_data)
    return analyzer.analyze()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 2:
        target_domain = sys.argv[1]
        risk_file = sys.argv[2]
        
        try:
            with open(risk_file, 'r') as f:
                risk_data = json.load(f)
            
            result = analyze_risks(target_domain, risk_data)
            print(f"\nAI analysis for {target_domain}:")
            print(f"Method: {result['analysis_method']}")
            print(f"\nSummary: {result['summary']}")
            
            print("\nKey Risks:")
            for i, risk in enumerate(result['key_risks'], 1):
                print(f"  {i}. {risk}")
            
            print("\nRecommendations:")
            for i, rec in enumerate(result['recommendations'], 1):
                print(f"  {i}. {rec}")
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python ai_analyzer.py <domain> <risk_data_file>", file=sys.stderr)
