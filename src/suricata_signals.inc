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

static bool containsAny(const std::string& value, const std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

static SignalType mapSuricataTextToSignal(const std::string& signature, const std::string& category) {
    std::string text = lowerCopy(signature + " " + category);

    if (containsAny(text, {"prompt injection", "jailbreak", "ignore previous"}))
        return SIG_PROMPT_INJECTION;
    if (containsAny(text, {"tool abuse", "shell", "bash", "powershell", "kubectl", "docker.sock"}))
        return SIG_TOOL_ABUSE;
    if (containsAny(text, {"lateral movement", "psexec", "winrm", "ssh ", "scp "}))
        return SIG_LATERAL_MOVEMENT;
    if (containsAny(text, {"resources/read", "resources/list", ".aws/credentials", ".ssh/", ".env"}))
        return SIG_MCP_RESOURCE_ACCESS;
    if (containsAny(text, {"prompt access", "prompts/get", "system prompt", "confidential prompt"}))
        return SIG_MCP_PROMPT_ACCESS;
    if (containsAny(text, {"sampling request", "sampling/createmessage", "sampling/create_message"}))
        return SIG_MCP_SAMPLING_REQUEST;
    if (containsAny(text, {"elicitation request", "elicitation/create"}))
        return SIG_MCP_ELICITATION_REQUEST;
    if (containsAny(text, {"mcp auth bypass", "mcp privilege escalation", "admin tool call", "all-tenants", "cluster-admin"}))
        return SIG_MCP_TOOL_CALL;
    if (containsAny(text, {"a2a content type", "application/a2a+json", "a2a-version"}))
        return SIG_A2A_HTTP;
    if (containsAny(text, {"a2a agent card", "agent-card.json", "extended agent card"}))
        return SIG_A2A_AGENT_CARD_DISCOVERY;
    if (containsAny(text, {"a2a message send", "message:send", "message:stream"}))
        return SIG_A2A_MESSAGE_SEND;
    if (containsAny(text, {"a2a task operation", "task access", "tasks/"}))
        return SIG_A2A_TASK_ACCESS;
    if (containsAny(text, {"a2a push notification", "push notification config", "webhook"}))
        return SIG_A2A_PUSH_NOTIFICATION;
    if (containsAny(text, {"a2a artifact", "artifact external url", "artifact exfil"}))
        return SIG_A2A_ARTIFACT_EXFIL;
    if (containsAny(text, {"a2a auth required", "task_state_auth_required"}))
        return SIG_A2A_AUTH_REQUIRED;
    if (containsAny(text, {"ssrf", "metadata service", "169.254.169.254"}))
        return SIG_REST_SSRF;
    if (containsAny(text, {"bulk export", "data exfiltration", "data exfil"}))
        return SIG_REST_DATA_EXFIL;
    if (containsAny(text, {"secret response", "secret_response", "credential leak", "private key"}))
        return SIG_SECRET_ACCESS;
    if (containsAny(text, {"jwt abuse", "refresh_token", "access_token"}))
        return SIG_REST_JWT_ABUSE;
    if (containsAny(text, {"rest auth", "authentication bypass", "auth bypass"}))
        return SIG_REST_AUTH_BYPASS;
    if (containsAny(text, {"graphql introspection", "endpoint probing"}))
        return SIG_REST_ENDPOINT_PROBE;
    if (containsAny(text, {"scanner", "scan", "recon"}))
        return SIG_SCANNER;
    if (containsAny(text, {"protocol violation", "request smuggling", "malformed"}))
        return SIG_PROTOCOL_VIOLATION;
    if (containsAny(text, {"anomaly"}))
        return SIG_ANOMALY_BEHAVIOR;

    return SIG_UNKNOWN;
}

// SID mapping for the signatures shipped in ids-rules/suricata.rules.
SignalType suricataSidSignal(long sid) {
    // Provider observation rules use contiguous SID ranges.
    if (sid >= 1010000 && sid <= 1010013) return SIG_TLS_SNI_LLM;
    if (sid >= 1011000 && sid <= 1011013) return SIG_DNS_LLM;
    if (sid >= 1012000 && sid <= 1012013) return SIG_AI_PROVIDER_USAGE;
    switch (sid) {
        case 1000161:
        case 1000164:
            return SIG_A2A_AGENT_CARD_DISCOVERY;
        case 1000166:
            return SIG_A2A_ARTIFACT_EXFIL;
        case 1000167:
            return SIG_A2A_AUTH_REQUIRED;
        case 1000160:
            return SIG_A2A_HTTP;
        case 1000162:
            return SIG_A2A_MESSAGE_SEND;
        case 1000165:
            return SIG_A2A_PUSH_NOTIFICATION;
        case 1000163:
            return SIG_A2A_TASK_ACCESS;
        case 1000100:
        case 1000101:
        case 1000103:
        case 1000104:
        case 1000105:
        case 1000106:
            return SIG_HTTP_PATTERN;
        case 1000122:
            return SIG_LATERAL_MOVEMENT;
        case 1000133:
            return SIG_MCP_ELICITATION_REQUEST;
        case 1000131:
            return SIG_MCP_PROMPT_ACCESS;
        case 1000123:
            return SIG_MCP_RESOURCE_ACCESS;
        case 1000132:
            return SIG_MCP_SAMPLING_REQUEST;
        case 1000134:
        case 1000135:
            return SIG_MCP_TOOL_CALL;
        case 1000120:
            return SIG_PROMPT_INJECTION;
        case 1000143:
        case 1000148:
            return SIG_REST_AUTH_BYPASS;
        case 1000141:
        case 1000146:
            return SIG_REST_DATA_EXFIL;
        case 1000144:
        case 1000149:
            return SIG_REST_ENDPOINT_PROBE;
        case 1000142:
        case 1000147:
            return SIG_REST_JWT_ABUSE;
        case 1000140:
        case 1000145:
            return SIG_REST_SSRF;
        case 1000150:
            return SIG_SECRET_ACCESS;
        case 1000121:
            return SIG_TOOL_ABUSE;
        default:
            return SIG_UNKNOWN;
    }
}
