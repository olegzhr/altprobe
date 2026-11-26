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

#include "otlp.h"
#include "trace_config.h"
#include "bounded_json.h"
#include "json_wire.h"
#include "base64.h"
#include "helpers.h"
#include <google/protobuf/util/json_util.h>
#include <openssl/crypto.h>
#include <chrono>
#include <climits>

namespace {
using Span = opentelemetry::proto::trace::v1::Span;
using Attributes = google::protobuf::RepeatedPtrField<opentelemetry::proto::common::v1::KeyValue>;
std::string hex(const std::string& bytes) {
    const char* digits = "0123456789abcdef"; std::string out;
    for (unsigned char b : bytes) { out += digits[b>>4]; out += digits[b&15]; } return out;
}
std::string unhex(const std::string& value) {
    std::string out;
    if (value.size()%2 || value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) throw std::runtime_error("invalid OTLP identifier");
    for (size_t i=0;i<value.size();i+=2) out += static_cast<char>(std::stoi(value.substr(i,2),nullptr,16));
    return out;
}
void convertIds(Json& value,bool to_protobuf) {
    for (auto& item : value.children) {
        if ((item.first == "traceId" || item.first == "spanId" || item.first == "parentSpanId") && item.second.kind == 's') {
            auto& id = item.second.text;
            if (to_protobuf) { std::string out; Base64::Encode(unhex(id),&out); id = out; }
            else { std::string out; if (!Base64::Decode(id,&out)) throw std::runtime_error("invalid bytes"); id = hex(out); }
        } else convertIds(item.second,to_protobuf);
    }
}
bool nonzero(const std::string& bytes,size_t length) {
    return bytes.size()==length && bytes.find_first_not_of('\0') != std::string::npos;
}
std::string attribute(const Attributes& attrs,const std::string& name) {
    for (const auto& a : attrs) if (a.key()==name) {
        const auto& v=a.value();
        using Value = opentelemetry::proto::common::v1::AnyValue;
        if (v.value_case() == Value::kStringValue) return v.string_value();
        if (v.value_case() == Value::kIntValue) return std::to_string(v.int_value());
        if (v.value_case() == Value::kBoolValue) return v.bool_value() ? "true" : "false";
    }
    return "";
}
Json* field(Json& n,const std::string& name) {
    for (auto& child:n.children) if(child.first==name) return &child.second; return nullptr;
}
void stringAttr(Json& span,const std::string& key,const std::string& val) {
    auto attrs=field(span,"attributes");
    if(!attrs) { Json a;a.kind='a';span.children.push_back({"attributes",a});attrs=&span.children.back().second; }
    // The collector owns routing annotations; exporters cannot forge triggers.
    attrs->children.erase(std::remove_if(attrs->children.begin(),attrs->children.end(),[&](const auto& v){return v.second.string("key")==key;}),attrs->children.end());
    Json k;k.kind='s';k.text=key;Json s;s.kind='s';s.text=val;Json v;v.kind='o';v.children.push_back({"stringValue",s});
    Json a;a.kind='o';a.children={{"key",k},{"value",v}};attrs->children.push_back({"",a});
}
}
bool validateOtlp(const OtlpRequest& request,std::string& error) {
    size_t count=0;
    for(const auto& r:request.resource_spans()) for(const auto& scope:r.scope_spans()) for(const auto& span:scope.spans()) {
        if(++count>16384 || !nonzero(span.trace_id(),16) || !nonzero(span.span_id(),8) ||
            (!span.parent_span_id().empty() && span.parent_span_id().size()!=8) ||
            span.end_time_unix_nano()<span.start_time_unix_nano() || !span.start_time_unix_nano() ||
            span.end_time_unix_nano()/1000000 > static_cast<uint64_t>(LONG_MAX)) { error="invalid span IDs, timestamps or span limit";return false; }
        for(const auto& link:span.links()) if(!nonzero(link.trace_id(),16)||!nonzero(link.span_id(),8)) {error="invalid link IDs";return false;}
    }
    return true;
}
bool decodeOtlp(const std::string& body,bool json,OtlpRequest& out,std::string& error,size_t max_bytes) {
    try {
        const size_t limit = max_bytes ? max_bytes : static_cast<size_t>(traceConfig().collector.max_body_bytes);
        if(body.size()>limit) throw std::runtime_error("OTLP request too large");
        if(json) {
            Json value;
            if(!parseBoundedJson(body,value,limit,1048576)||value.kind!='o') throw std::runtime_error("invalid OTLP JSON");
            convertIds(value,true);
            google::protobuf::util::JsonParseOptions options;options.ignore_unknown_fields=true;
            if(!google::protobuf::util::JsonStringToMessage(wireJson(value),&out,options).ok()) throw std::runtime_error("invalid OTLP JSON fields");
        } else if(!out.ParseFromString(body)) throw std::runtime_error("invalid OTLP protobuf");
        return validateOtlp(out,error);
    } catch(const std::exception& e) {error=e.what();return false;}
}
std::string otlpJson(const OtlpRequest& request) {
    std::string body;
    google::protobuf::util::JsonPrintOptions options;
    options.always_print_enums_as_ints = true; // OTLP/JSON uses numeric enums, unlike default protobuf JSON.
    if(!google::protobuf::util::MessageToJsonString(request,&body,options).ok()) throw std::runtime_error("OTLP serialization failed");
    Json value;
    if(!parseBoundedJson(body,value,33554432,1048576)) throw std::runtime_error("OTLP JSON limit");
    convertIds(value,false);return wireJson(value);
}
std::vector<TraceEvent> externalTraceEvents(const OtlpRequest& request) {
    std::vector<TraceEvent> result;
    for(const auto& resource:request.resource_spans()) for(const auto& scope:resource.scope_spans()) for(const auto& span:scope.spans()) {
        auto attr=[&](std::initializer_list<const char*> names) {
            for(const auto* n:names) {auto s=attribute(span.attributes(),n);if(s.empty())s=attribute(resource.resource().attributes(),n);if(!s.empty())return s;} return std::string{};
        };
        TraceEvent e;e.source="otel";e.ts=span.start_time_unix_nano()/1000000;e.duration_ms=(span.end_time_unix_nano()-span.start_time_unix_nano())/1000000;
        e.agent_key=attr({"alertflex.agent.key","enduser.id"});
        if(e.agent_key.empty())e.agent_key="otel:trace:"+hex(span.trace_id());
        e.agent_key=truncateField(e.agent_key,512);e.identity_source="otel_exporter";e.trust_tier="trusted_exporter";
        e.request_id=hex(span.span_id());e.session_id=hex(span.trace_id());e.host_id=attr({"host.name","service.instance.id","service.name"});
        e.http_method=attr({"http.request.method","http.method"});e.url=attr({"url.full","http.url","url.path","http.target"});
        e.mcp_method=attr({"mcp.method","rpc.method"});e.track=attr({"alertflex.track"});
        if(e.track!="HTTP"&&e.track!="MCP"&&e.track!="A2A"&&e.track!="SECURITY") e.track=e.mcp_method.empty()?"HTTP":"MCP";
        auto status=attr({"http.response.status_code","http.status_code"});
        try{e.status=status.empty()?0:std::stoi(status);}catch(...){e.status=0;}
        e.operation_status=span.status().code()==2?2:1;e.operation_state="completed";
        auto body=attr({"http.request.body","http.request.body.content","gen_ai.input.messages"});
        if(body.empty())body=span.name();
        auto limits=limitsFor(e.track,e.url);auto req=processBody(body,limits.request_max,false);
        auto resp=processBody(attr({"http.response.body","http.response.body.content","gen_ai.output.messages"}),limits.response_max,false);
        e.request_body=req.value;e.response_body=resp.value;e.request_truncated=req.truncated;e.response_truncated=resp.truncated;
        e.request_original_size=req.original_size;e.response_original_size=resp.original_size;
        OtlpRequest single;auto* r=single.add_resource_spans();r->CopyFrom(resource);r->clear_scope_spans();
        // Tenant/asset routing belongs to this collector, never to exporter input.
        auto* attributes=r->mutable_resource()->mutable_attributes();
        for(int i=attributes->size()-1;i>=0;--i) if(attributes->Get(i).key()=="alertflex.project.id"||attributes->Get(i).key()=="alertflex.asset.name") attributes->DeleteSubrange(i,1);
        auto* project=r->mutable_resource()->add_attributes();project->set_key("alertflex.project.id");project->mutable_value()->set_string_value(CObject::project_id);
        auto* asset=r->mutable_resource()->add_attributes();asset->set_key("alertflex.asset.name");asset->mutable_value()->set_string_value(CObject::asset_name);
        auto* s=r->add_scope_spans();s->CopyFrom(scope);s->clear_spans();s->add_spans()->CopyFrom(span);
        e.external_otlp=otlpJson(single);result.push_back(std::move(e));
    }
    return result;
}
std::string externalTriggeredTrace(const std::vector<TraceEvent>& chain,const TracePattern& pattern,const std::string& agent,long fired_at) {
    Json root;root.kind='o';Json resources;resources.kind='a';
    for(const auto& e:chain) {
        Json part;if(!parseBoundedJson(e.external_otlp,part,33554432,1048576))continue;
        auto rs=field(part,"resourceSpans");if(!rs)continue;
        for(auto& resource:rs->children) {
            auto scopes=field(resource.second,"scopeSpans");if(!scopes)continue;
            for(auto& scope:scopes->children) {
                auto spans=field(scope.second,"spans");if(!spans)continue;
                for(auto& span:spans->children) {
                    stringAttr(span.second,"alertflex.trigger.id",pattern.id);stringAttr(span.second,"alertflex.agent.key",agent);
                    stringAttr(span.second,"alertflex.track",pattern.track);stringAttr(span.second,"alertflex.trace.source","otel");
                    stringAttr(span.second,"alertflex.trace.fired_at_unix_ms",std::to_string(fired_at));
                    stringAttr(span.second,"alertflex.trace.event_count",std::to_string(chain.size()));
                    stringAttr(span.second,"alertflex.pattern.severity",std::to_string(pattern.pattern_severity));
                }
            }
            resources.children.push_back(std::move(resource));
        }
    }
    root.children.push_back({"resourceSpans",resources});return wireJson(root);
}
