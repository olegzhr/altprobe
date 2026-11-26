/*
 *   Copyright 2021-2026 Oleg Zharkov
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

#include "mitre.h"

std::string mitreFramework(SignalType signal) {
    switch (signal) {
        case SIG_PROMPT_INJECTION:
            return "MITRE ATLAS";
        case SIG_UNKNOWN:
            return "unknown";
        default:
            return "MITRE ATT&CK Enterprise";
    }
}

std::string mitreTactic(SignalType signal) {
    switch (signal) {
        case SIG_PROMPT_INJECTION:
        case SIG_PROC_SPAWN_AI:
        case SIG_PROC_BEHAVIOR:
        case SIG_TOOL_ABUSE:
        case SIG_MCP_TOOL_CALL:
        case SIG_A2A_MESSAGE_SEND:
        case SIG_A2A_TASK_CANCEL:
        case SIG_RCE:
            return "Execution";

        case SIG_MCP_IPC:
        case SIG_MCP_STDIO:
            return "Execution";

        case SIG_TLS_SNI_LLM:
        case SIG_DNS_LLM:
        case SIG_TLS_CERT_LLM:
        case SIG_ASN_LLM:
        case SIG_AI_PROVIDER_USAGE:
        case SIG_AI_GATEWAY_CONTEXT:
        case SIG_PROC_NET_CLIENT:
        case SIG_MCP_SAMPLING_REQUEST:
        case SIG_A2A_PUSH_NOTIFICATION:
            return "Command and Control";

        case SIG_SECRET_ACCESS:
        case SIG_REST_JWT_ABUSE:
        case SIG_A2A_AUTH_REQUIRED:
            return "Credential Access";

        case SIG_MCP_RESOURCE_ACCESS:
        case SIG_MCP_PROMPT_ACCESS:
        case SIG_MCP_UNKNOWN_RESOURCE:
        case SIG_MCP_UNKNOWN_PROMPT:
        case SIG_MCP_ELICITATION_REQUEST:
        case SIG_A2A_TASK_ACCESS:
        case SIG_CORPORATE_DATA_CONTEXT:
            return "Collection";

        case SIG_REST_DATA_EXFIL:
        case SIG_A2A_ARTIFACT_EXFIL:
            return "Exfiltration";

        case SIG_LATERAL_MOVEMENT:
            return "Lateral Movement";

        case SIG_HTTP_PATTERN:
        case SIG_MCP_HTTP:
        case SIG_MCP_TOOL_LIST:
        case SIG_MCP_INVENTORY_DISCOVERY:
        case SIG_A2A_HTTP:
        case SIG_A2A_AGENT_CARD_DISCOVERY:
        case SIG_REST_API_CALL:
        case SIG_REST_ENDPOINT_PROBE:
        case SIG_SCANNER:
        case SIG_SMALL_TLS_REQ:
        case SIG_TLS_BURST:
        case SIG_REPETITIVE_TLS_PATTERN:
        case SIG_ANOMALY_BEHAVIOR:
        case SIG_ANOMALY:
            return "Discovery";

        case SIG_REST_AUTH_BYPASS:
        case SIG_REST_SSRF:
        case SIG_USER_FRAUD_CONTEXT:
        case SIG_SQLI:
        case SIG_XSS:
        case SIG_PATH_TRAVERSAL:
        case SIG_LFI:
        case SIG_RFI:
        case SIG_PROTOCOL_VIOLATION:
            return "Initial Access";

        case SIG_MCP_INVENTORY_CHANGE:
        case SIG_MCP_UNKNOWN_TOOL:
        case SIG_MCP_ENDPOINT_DRIFT:
        case SIG_A2A_AGENT_CARD_CHANGE:
        case SIG_A2A_UNKNOWN_AGENT:
            return "Defense Evasion";

        case SIG_LONG_TLS_SESSION:
        case SIG_REST_RATE_LIMIT_ABUSE:
            return "Impact";

        case SIG_ATTACK_PIPELINE:
        case SIG_MCP_CHAIN_STAGE:
            return "Multiple";

        default:
            return "unknown";
    }
}

std::string mitreTechniqueId(SignalType signal) {
    switch (signal) {
        case SIG_PROMPT_INJECTION:
            return "AML.T0051";

        case SIG_MCP_IPC:
        case SIG_MCP_STDIO:
            return "T1559";

        case SIG_PROC_SPAWN_AI:
        case SIG_PROC_BEHAVIOR:
        case SIG_TOOL_ABUSE:
            return "T1059";

        case SIG_MCP_TOOL_CALL:
        case SIG_A2A_MESSAGE_SEND:
        case SIG_A2A_TASK_CANCEL:
            return "T1106";

        case SIG_PROC_NET_CLIENT:
        case SIG_TLS_SNI_LLM:
        case SIG_TLS_CERT_LLM:
        case SIG_ASN_LLM:
        case SIG_AI_PROVIDER_USAGE:
        case SIG_AI_GATEWAY_CONTEXT:
        case SIG_MCP_SAMPLING_REQUEST:
        case SIG_A2A_PUSH_NOTIFICATION:
            return "T1071.001";

        case SIG_DNS_LLM:
            return "T1071.004";

        case SIG_SECRET_ACCESS:
            return "T1552";

        case SIG_REST_JWT_ABUSE:
        case SIG_REST_AUTH_BYPASS:
        case SIG_A2A_AUTH_REQUIRED:
        case SIG_USER_FRAUD_CONTEXT:
            return "T1078";

        case SIG_MCP_RESOURCE_ACCESS:
        case SIG_MCP_PROMPT_ACCESS:
        case SIG_MCP_UNKNOWN_RESOURCE:
        case SIG_MCP_UNKNOWN_PROMPT:
        case SIG_A2A_TASK_ACCESS:
        case SIG_CORPORATE_DATA_CONTEXT:
            return "T1005";

        case SIG_MCP_ELICITATION_REQUEST:
            return "T1056";

        case SIG_REST_DATA_EXFIL:
        case SIG_A2A_ARTIFACT_EXFIL:
            return "T1041";

        case SIG_LATERAL_MOVEMENT:
            return "T1021";

        case SIG_HTTP_PATTERN:
        case SIG_MCP_HTTP:
        case SIG_MCP_TOOL_LIST:
        case SIG_MCP_INVENTORY_DISCOVERY:
        case SIG_A2A_HTTP:
        case SIG_A2A_AGENT_CARD_DISCOVERY:
        case SIG_REST_API_CALL:
        case SIG_REST_ENDPOINT_PROBE:
        case SIG_SCANNER:
        case SIG_SMALL_TLS_REQ:
        case SIG_TLS_BURST:
        case SIG_REPETITIVE_TLS_PATTERN:
        case SIG_ANOMALY_BEHAVIOR:
        case SIG_ANOMALY:
            return "T1595";

        case SIG_REST_SSRF:
        case SIG_SQLI:
        case SIG_XSS:
        case SIG_RCE:
        case SIG_PATH_TRAVERSAL:
        case SIG_LFI:
        case SIG_RFI:
        case SIG_PROTOCOL_VIOLATION:
            return "T1190";

        case SIG_MCP_INVENTORY_CHANGE:
        case SIG_MCP_UNKNOWN_TOOL:
        case SIG_MCP_ENDPOINT_DRIFT:
        case SIG_A2A_AGENT_CARD_CHANGE:
        case SIG_A2A_UNKNOWN_AGENT:
            return "T1565";

        case SIG_LONG_TLS_SESSION:
        case SIG_REST_RATE_LIMIT_ABUSE:
            return "T1499";

        case SIG_ATTACK_PIPELINE:
        case SIG_MCP_CHAIN_STAGE:
            return "multiple";

        default:
            return "unknown";
    }
}

std::string mitreTechniqueName(SignalType signal) {
    switch (signal) {
        case SIG_PROMPT_INJECTION:
            return "LLM Prompt Injection";
        case SIG_MCP_IPC:
        case SIG_MCP_STDIO:
            return "Inter-Process Communication";
        case SIG_PROC_SPAWN_AI:
        case SIG_PROC_BEHAVIOR:
        case SIG_TOOL_ABUSE:
            return "Command and Scripting Interpreter";
        case SIG_MCP_TOOL_CALL:
        case SIG_A2A_MESSAGE_SEND:
        case SIG_A2A_TASK_CANCEL:
            return "Native API";
        case SIG_PROC_NET_CLIENT:
        case SIG_TLS_SNI_LLM:
        case SIG_TLS_CERT_LLM:
        case SIG_ASN_LLM:
        case SIG_AI_PROVIDER_USAGE:
        case SIG_AI_GATEWAY_CONTEXT:
        case SIG_MCP_SAMPLING_REQUEST:
        case SIG_A2A_PUSH_NOTIFICATION:
            return "Application Layer Protocol: Web Protocols";
        case SIG_DNS_LLM:
            return "Application Layer Protocol: DNS";
        case SIG_SECRET_ACCESS:
            return "Unsecured Credentials";
        case SIG_REST_JWT_ABUSE:
        case SIG_REST_AUTH_BYPASS:
        case SIG_A2A_AUTH_REQUIRED:
        case SIG_USER_FRAUD_CONTEXT:
            return "Valid Accounts";
        case SIG_MCP_RESOURCE_ACCESS:
        case SIG_MCP_PROMPT_ACCESS:
        case SIG_MCP_UNKNOWN_RESOURCE:
        case SIG_MCP_UNKNOWN_PROMPT:
        case SIG_A2A_TASK_ACCESS:
        case SIG_CORPORATE_DATA_CONTEXT:
            return "Data from Local System";
        case SIG_MCP_ELICITATION_REQUEST:
            return "Input Capture";
        case SIG_REST_DATA_EXFIL:
        case SIG_A2A_ARTIFACT_EXFIL:
            return "Exfiltration Over C2 Channel";
        case SIG_LATERAL_MOVEMENT:
            return "Remote Services";
        case SIG_HTTP_PATTERN:
        case SIG_MCP_HTTP:
        case SIG_MCP_TOOL_LIST:
        case SIG_MCP_INVENTORY_DISCOVERY:
        case SIG_A2A_HTTP:
        case SIG_A2A_AGENT_CARD_DISCOVERY:
        case SIG_REST_API_CALL:
        case SIG_REST_ENDPOINT_PROBE:
        case SIG_SCANNER:
        case SIG_SMALL_TLS_REQ:
        case SIG_TLS_BURST:
        case SIG_REPETITIVE_TLS_PATTERN:
        case SIG_ANOMALY_BEHAVIOR:
        case SIG_ANOMALY:
            return "Active Scanning";
        case SIG_REST_SSRF:
        case SIG_SQLI:
        case SIG_XSS:
        case SIG_RCE:
        case SIG_PATH_TRAVERSAL:
        case SIG_LFI:
        case SIG_RFI:
        case SIG_PROTOCOL_VIOLATION:
            return "Exploit Public-Facing Application";
        case SIG_MCP_INVENTORY_CHANGE:
        case SIG_MCP_UNKNOWN_TOOL:
        case SIG_MCP_ENDPOINT_DRIFT:
        case SIG_A2A_AGENT_CARD_CHANGE:
        case SIG_A2A_UNKNOWN_AGENT:
            return "Data Manipulation";
        case SIG_LONG_TLS_SESSION:
        case SIG_REST_RATE_LIMIT_ABUSE:
            return "Endpoint Denial of Service";
        case SIG_ATTACK_PIPELINE:
        case SIG_MCP_CHAIN_STAGE:
            return "Multiple Techniques";
        default:
            return "unknown";
    }
}

