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

#include "detection.h"

std::string signalName(SignalType signal) {
    switch (signal) {
        case SIG_MCP_IPC: return "SIG_MCP_IPC";
        case SIG_MCP_STDIO: return "SIG_MCP_STDIO";
        case SIG_PROC_SPAWN_AI: return "SIG_PROC_SPAWN_AI";
        case SIG_PROC_NET_CLIENT: return "SIG_PROC_NET_CLIENT";
        case SIG_PROC_BEHAVIOR: return "SIG_PROC_BEHAVIOR";
        case SIG_TLS_JA3_AI: return "SIG_TLS_JA3_AI";
        case SIG_SMALL_TLS_REQ: return "SIG_SMALL_TLS_REQ";
        case SIG_TLS_BURST: return "SIG_TLS_BURST";
        case SIG_LONG_TLS_SESSION: return "SIG_LONG_TLS_SESSION";
        case SIG_REPETITIVE_TLS_PATTERN: return "SIG_REPETITIVE_TLS_PATTERN";
        case SIG_ANOMALY_BEHAVIOR: return "SIG_ANOMALY_BEHAVIOR";
        case SIG_HTTP_PATTERN: return "SIG_HTTP_PATTERN";
        case SIG_TLS_SNI_LLM: return "SIG_TLS_SNI_LLM";
        case SIG_DNS_LLM: return "SIG_DNS_LLM";
        case SIG_TLS_CERT_LLM: return "SIG_TLS_CERT_LLM";
        case SIG_ASN_LLM: return "SIG_ASN_LLM";
        case SIG_MCP_HTTP: return "SIG_MCP_HTTP";
        case SIG_MCP_TOOL_LIST: return "SIG_MCP_TOOL_LIST";
        case SIG_MCP_TOOL_CALL: return "SIG_MCP_TOOL_CALL";
        case SIG_MCP_RESOURCE_ACCESS: return "SIG_MCP_RESOURCE_ACCESS";
        case SIG_PROMPT_INJECTION: return "SIG_PROMPT_INJECTION";
        case SIG_TOOL_ABUSE: return "SIG_TOOL_ABUSE";
        case SIG_LATERAL_MOVEMENT: return "SIG_LATERAL_MOVEMENT";
        case SIG_SECRET_ACCESS: return "SIG_SECRET_ACCESS";
        case SIG_AI_PROVIDER_USAGE: return "SIG_AI_PROVIDER_USAGE";
        case SIG_AI_GATEWAY_CONTEXT: return "SIG_AI_GATEWAY_CONTEXT";
        case SIG_CORPORATE_DATA_CONTEXT: return "SIG_CORPORATE_DATA_CONTEXT";
        case SIG_MCP_CHAIN_STAGE: return "SIG_MCP_CHAIN_STAGE";
        case SIG_ATTACK_PIPELINE: return "SIG_ATTACK_PIPELINE";
        case SIG_MCP_INVENTORY_DISCOVERY: return "SIG_MCP_INVENTORY_DISCOVERY";
        case SIG_MCP_INVENTORY_CHANGE: return "SIG_MCP_INVENTORY_CHANGE";
        case SIG_MCP_UNKNOWN_TOOL: return "SIG_MCP_UNKNOWN_TOOL";
        case SIG_MCP_UNKNOWN_RESOURCE: return "SIG_MCP_UNKNOWN_RESOURCE";
        case SIG_MCP_UNKNOWN_PROMPT: return "SIG_MCP_UNKNOWN_PROMPT";
        case SIG_MCP_ENDPOINT_DRIFT: return "SIG_MCP_ENDPOINT_DRIFT";
        case SIG_MCP_PROMPT_ACCESS: return "SIG_MCP_PROMPT_ACCESS";
        case SIG_MCP_SAMPLING_REQUEST: return "SIG_MCP_SAMPLING_REQUEST";
        case SIG_MCP_ELICITATION_REQUEST: return "SIG_MCP_ELICITATION_REQUEST";
        case SIG_A2A_HTTP: return "SIG_A2A_HTTP";
        case SIG_A2A_AGENT_CARD_DISCOVERY: return "SIG_A2A_AGENT_CARD_DISCOVERY";
        case SIG_A2A_AGENT_CARD_CHANGE: return "SIG_A2A_AGENT_CARD_CHANGE";
        case SIG_A2A_MESSAGE_SEND: return "SIG_A2A_MESSAGE_SEND";
        case SIG_A2A_TASK_ACCESS: return "SIG_A2A_TASK_ACCESS";
        case SIG_A2A_TASK_CANCEL: return "SIG_A2A_TASK_CANCEL";
        case SIG_A2A_PUSH_NOTIFICATION: return "SIG_A2A_PUSH_NOTIFICATION";
        case SIG_A2A_ARTIFACT_EXFIL: return "SIG_A2A_ARTIFACT_EXFIL";
        case SIG_A2A_AUTH_REQUIRED: return "SIG_A2A_AUTH_REQUIRED";
        case SIG_A2A_UNKNOWN_AGENT: return "SIG_A2A_UNKNOWN_AGENT";
        case SIG_REST_API_CALL: return "SIG_REST_API_CALL";
        case SIG_REST_AUTH_BYPASS: return "SIG_REST_AUTH_BYPASS";
        case SIG_REST_DATA_EXFIL: return "SIG_REST_DATA_EXFIL";
        case SIG_REST_RATE_LIMIT_ABUSE: return "SIG_REST_RATE_LIMIT_ABUSE";
        case SIG_REST_ENDPOINT_PROBE: return "SIG_REST_ENDPOINT_PROBE";
        case SIG_SHADOW_API: return "SIG_SHADOW_API";
        case SIG_REST_SSRF: return "SIG_REST_SSRF";
        case SIG_REST_JWT_ABUSE: return "SIG_REST_JWT_ABUSE";
        case SIG_USER_FRAUD_CONTEXT: return "SIG_USER_FRAUD_CONTEXT";
        case SIG_SQLI: return "SIG_SQLI";
        case SIG_XSS: return "SIG_XSS";
        case SIG_RCE: return "SIG_RCE";
        case SIG_PATH_TRAVERSAL: return "SIG_PATH_TRAVERSAL";
        case SIG_LFI: return "SIG_LFI";
        case SIG_RFI: return "SIG_RFI";
        case SIG_PROTOCOL_VIOLATION: return "SIG_PROTOCOL_VIOLATION";
        case SIG_SCANNER: return "SIG_SCANNER";
        case SIG_ANOMALY: return "SIG_ANOMALY";
        default: return "SIG_UNKNOWN";
    }
}
