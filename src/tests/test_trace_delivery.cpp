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

#include "trace_delivery.h"
#include "trace_config.h"
#include "otlp_receiver.h"
#include "otlp.h"
#include "inventory.h"
#include "http_io.h"
#include "bounded_json.h"
#include "opentelemetry/proto/collector/trace/v1/trace_service.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <filesystem>
#include <cassert>
#include <thread>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <zlib.h>

using namespace std::chrono_literals;
namespace net=boost::asio;namespace http=boost::beast::http;using tcp=net::ip::tcp;
class Peer {
    net::io_context ioc;tcp::acceptor acceptor{ioc,{net::ip::make_address("127.0.0.1"),0}};
    std::atomic<bool> stopped{false};std::thread worker;
public:
    std::atomic<unsigned> status{200};std::mutex mutex;
    struct Call{std::string method,target,body;};std::vector<Call> calls;
    std::string responseBody=R"({"status":"stored","id":1})";
    std::string url()const{return "http://127.0.0.1:"+std::to_string(acceptor.local_endpoint().port());}
    Peer(){acceptor.non_blocking(true);worker=std::thread([this]{
        while(!stopped){
            tcp::socket socket(ioc);boost::system::error_code ec;acceptor.accept(socket,ec);
            if(ec){std::this_thread::sleep_for(5ms);continue;}
            boost::beast::flat_buffer buffer;http::request<http::string_body> req;http::read(socket,buffer,req,ec);
            if(ec)continue;
            {std::lock_guard<std::mutex> lock(mutex);calls.push_back({std::string(req.method_string()),std::string(req.target()),req.body()});}
            http::response<http::string_body> res{static_cast<http::status>(status.load()),11};
            {std::lock_guard<std::mutex> lock(mutex);res.body()=responseBody;}res.prepare_payload();http::write(socket,res,ec);
        }
    });}
    ~Peer(){stopped=true;worker.join();}
    size_t count(){std::lock_guard<std::mutex> lock(mutex);return calls.size();}
    Call last(){std::lock_guard<std::mutex> lock(mutex);return calls.back();}
};
template<class F>void waitFor(F f){auto end=std::chrono::steady_clock::now()+8s;while(!f()&&std::chrono::steady_clock::now()<end)std::this_thread::sleep_for(20ms);assert(f());}
void env(const char* key,const std::string& value){setenv(key,value.c_str(),1);}
void config(){std::string error;assert(loadTraceConfig(2,error));}
size_t files(const std::string& base,const std::string& channel,const std::string& ext=".json"){
    size_t n=0;for(const auto& p:std::filesystem::recursive_directory_iterator(base))if(p.path().extension()==ext&&p.path().parent_path().filename()==channel)++n;return n;
}
OtlpRequest sample(){
    OtlpRequest req;auto* r=req.add_resource_spans();auto* service=r->mutable_resource()->add_attributes();service->set_key("service.name");service->mutable_value()->set_string_value("gateway");
    auto* s=r->add_scope_spans()->add_spans();s->set_trace_id(std::string(16,'t'));s->set_span_id(std::string(8,'s'));s->set_name("external-operation");s->set_kind(opentelemetry::proto::trace::v1::Span::SPAN_KIND_SERVER);
    auto now=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();s->set_start_time_unix_nano(now);s->set_end_time_unix_nano(now+1000000);
    auto* a=s->add_attributes();a->set_key("http.request.body");a->mutable_value()->set_string_value("EXTERNAL_TRIGGER");
    a=s->add_attributes();a->set_key("alertflex.agent.key");a->mutable_value()->set_string_value("agent-external");return req;
}
std::string gzip(const std::string& input){
    z_stream z{};assert(deflateInit2(&z,Z_DEFAULT_COMPRESSION,Z_DEFLATED,16+MAX_WBITS,8,Z_DEFAULT_STRATEGY)==Z_OK);
    std::string output(input.size()+256,'\0');z.next_in=reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));z.avail_in=input.size();
    z.next_out=reinterpret_cast<Bytef*>(&output[0]);z.avail_out=output.size();assert(deflate(&z,Z_FINISH)==Z_STREAM_END);output.resize(z.total_out);deflateEnd(&z);return output;
}
struct TraceIntegrationTest {
    static void patterns(Trace& t){TracePattern p;p.id="external-trigger";p.source="otel";p.min_events=1;p.cooldown_sec=0;TraceCondition c;c.body_contains="EXTERNAL_TRIGGER";p.conditions.push_back(c);t.patterns_={p};t.last_patterns_version_=Filter::getInventoryVersion();}
};
struct InventoryIntegrationTest { static bool fetch(Filter& f){return f.fetchInventory();} };
int main(){
    CObject::run_mode=2;CObject::stopping=false;CObject::project_id="trace-test";CObject::asset_name="test-asset";CObject::host_name="test-host";
    auto base="/tmp/altprobe-trace-test-"+std::to_string(getpid());env("SINKS_TRACE_SPOOL_DIR",base);env("SINKS_TRACE_TIMEOUT_MS","500");
    env("TRACE_MODE","internal");env("SINKS_OS_TYPES","OCSF,HTTP,OTEL");config();
    Peer os,af,gl;CObject::os_url=os.url();CObject::af_url=af.url()+"/api/v1";CObject::af_key="token";CObject::os_user="user";CObject::os_pwd="password";CObject::af_enable=CObject::os_enable=true;
    CObject::graylog_url=gl.url()+"/gelf";CObject::graylog_enable=true;
    {
        {std::lock_guard<std::mutex> lock(af.mutex);af.responseBody=R"({"asset":"test-asset","projectId":"trace-test","policyTargetVersion":1,"endpoints":[{"path":"/http-test","method":"POST","type":"REST","pipeline":"endpoint-anomaly","logBody":1,"blockStatus":"active"}],"patterns":[]})";}
        Filter filter;assert(InventoryIntegrationTest::fetch(filter));Inventory inventory;Http request{};request.url="/http-test";request.http_method="POST";
        Endpoint endpoint;assert(inventory.matchEndpoint(request,TYPE_REST,endpoint));assert(endpoint.pipeline=="endpoint-anomaly");
        auto discovery = [&](const std::string& agent) {
            std::lock_guard<std::mutex> lock(af.mutex);
            af.responseBody = R"({"asset":"test-asset","projectId":"trace-test","policyTargetVersion":2,"agentAuthVersion":1,"requireAgentKey":false,"agents":[)" + agent + R"(],"endpoints":[],"patterns":[]})";
        };
        const std::string discovered = R"({"id":"7","assetName":"test-asset","correlationUid":"","blockStatus":"active"})";
        discovery(discovered); assert(InventoryIntegrationTest::fetch(filter));
        auto snapshot = Filter::getInventorySnapshot();
        assert(snapshot->agents.size() == 1 && snapshot->agents[0].bindingAssetName.empty());
        assert(snapshot->agents[0].correlationUid.empty());
        const auto version = snapshot->version;
        discovery(R"({"id":"7","assetName":"test-asset","bindingAssetName":"test-asset","correlationUid":"","blockStatus":"active"})");
        assert(!InventoryIntegrationTest::fetch(filter)); assert(Filter::getInventorySnapshot()->version == version);
        discovery(R"({"id":"7","assetName":"test-asset","correlationUid":"auth:envoy:agent","blockStatus":"active"})");
        assert(InventoryIntegrationTest::fetch(filter));
        assert(Filter::getInventorySnapshot()->agents[0].bindingAssetName == "test-asset");
        {std::lock_guard<std::mutex> lock(af.mutex);af.responseBody=R"({"status":"stored","id":1})";}
    }
    // Existing endpoint pipeline is preserved only for HTTP OCSF, for full/light payloads alike.
    Sinks sink;
    assert(sink.sendOcsfToLogSinks("{}",4002,"endpoint-anomaly","proxy"));assert(os.last().target.find("?pipeline=endpoint-anomaly")!=std::string::npos);
    assert(sink.sendOcsfToLogSinks("{}",6003,"must-not-apply","correlator"));assert(os.last().target.find("pipeline=")==std::string::npos);
    assert(sink.sendOcsfToLogSinks("{}",4002,"indef","proxy"));assert(os.last().target.find("pipeline=")==std::string::npos);
    env("SINKS_OS_TYPES","OCSF");config();auto before=os.count();assert(sink.sendOcsfToLogSinks("{}",4002,"p","proxy"));assert(os.count()==before);
    env("SINKS_OS_TYPES","HTTP");config();assert(sink.sendOcsfToLogSinks("{}",6003,"p","correlator"));assert(os.count()==before);
    env("SINKS_OS_TYPES","OTEL");config();
    assert(sink.sendOcsfToLogSinks("{}",6003,"indef","openshell"));assert(os.count()==before);
    env("SINKS_OS_TYPES","OCSF,HTTP,OTEL");config();
    assert(sink.sendOcsfToLogSinks(R"({"metadata":{"project_id":"foreign","version":"1.8.0"}})",6003,"indef","openshell"));
    Json indexed;
    assert(parseBoundedJson(os.last().body, indexed));
    assert(indexed.get("metadata")->string("project_id") == "trace-test");
    assert(indexed.get("metadata")->string("version") == "1.8.0");
    // Graylog GELF HTTP input is an independent third stream (OCSF/HTTP/OTEL).
    auto gl_before=gl.count();
    assert(sink.sendOcsfToLogSinks(R"({"class_uid":6003,"metadata":{}})",6003,"indef","correlator"));
    assert(gl.count()==gl_before+1);
    auto gelf=gl.last();assert(gelf.method=="POST"&&gelf.target=="/gelf");
    assert(gelf.body.find("\"version\":\"1.1\"")!=std::string::npos);
    assert(gelf.body.find("\"_ocsf_class_uid\":6003")!=std::string::npos);
    assert(gelf.body.find("\"_altprobe_source\":\"correlator\"")!=std::string::npos);
    assert(gelf.body.find("\"_project_id\":\"trace-test\"")!=std::string::npos);
    assert(gelf.body.find("\"full_message\":\"{\\\"class_uid\\\":6003,\\\"metadata\\\":{}}\"")!=std::string::npos);
    CObject::graylog_http=false;gl_before=gl.count();
    assert(sink.sendOcsfToLogSinks("{}",4002,"p","proxy"));assert(gl.count()==gl_before);
    assert(sink.sendOcsfToLogSinks("{}",6003,"p","correlator"));assert(gl.count()==gl_before+1);
    CObject::graylog_http=true;
    gl.status=202;gl_before=gl.count();
    assert(sink.sendOcsfToLogSinks("{}",6003,"p","correlator"));assert(gl.count()==gl_before+1);
    gl.status=200;
    gl_before=gl.count();assert(sink.sendTraceToGraylog(R"({"resourceSpans":[]})"));assert(gl.count()==gl_before+1);
    assert(gl.last().body.find("\"_stream\":\"otel\"")!=std::string::npos);
    auto request=sample();auto body=otlpJson(request);std::string error;OtlpRequest decoded;
    assert(body.find("\"kind\":2")!=std::string::npos);
    if(!decodeOtlp(body,true,decoded,error)){std::cerr<<"OTLP decode: "<<error<<" body="<<body<<"\n";assert(false);}assert(decoded.resource_spans(0).scope_spans(0).spans(0).trace_id()==std::string(16,'t'));
    assert(decodeOtlp(request.SerializeAsString(),false,decoded,error));assert(!decodeOtlp(R"({"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"bad"}]}]}]})",true,decoded,error));
    // An outage in Graylog has its own retry worker. It neither delays further
    // traces in OpenSearch/Splunk nor repeats their successful deliveries.
    {
        Peer splunk;
        CObject::splunk_enable = CObject::splunk_otel = true;
        CObject::splunk_url = splunk.url(); CObject::splunk_token = "fixture";
        const auto initial_graylog = gl.count();
        const auto initial_opensearch = os.count();
        gl.status = 503;
        TraceDelivery delivery;
        assert(delivery.Open());
        std::thread worker([&]{ delivery.Go(); });
        size_t next = 0;
        assert(delivery.stageSinks(body, next));
        waitFor([&]{ return gl.count() > initial_graylog && splunk.count() == 1; });
        next = 0;
        assert(delivery.stageSinks(body + " ", next));
        waitFor([&]{ return splunk.count() == 2 && os.count() >= initial_opensearch + 2; });
        waitFor([&]{ return gl.count() >= initial_graylog + 3; });
        assert(splunk.count() == 2 && os.count() == initial_opensearch + 2);
        gl.status = 200;
        delivery.Close(); worker.join();
        CObject::splunk_enable = CObject::splunk_otel = false;
    }
    // Persist before I/O; a new delivery object recovers exactly the same body.
    af.status=503;
    {TraceDelivery first;assert(first.Open());assert(first.alertflex(body));assert(files(base,"alertflex")==1);first.Close();}
    before=os.count();auto af_before=af.count();
    {TraceDelivery recovered;assert(recovered.Open());assert(recovered.opensearch(body));std::thread worker([&]{recovered.Go();});
        waitFor([&]{return af.count()>af_before&&os.count()>before;});assert(files(base,"alertflex")==1);assert(os.last().method=="PUT");assert(os.last().target.find("pipeline=")==std::string::npos);
        assert(af.last().body==body);af.status=201;waitFor([&]{return files(base,"alertflex")==0;});recovered.Close();worker.join();}
    // Permanent errors remain private for operator review rather than disappearing.
    af.status=401;
    {TraceDelivery delivery;assert(delivery.Open());assert(delivery.alertflex(body+" "));std::thread worker([&]{delivery.Go();});waitFor([&]{return files(base,"alertflex",".rejected")==1;});delivery.Close();worker.join();}
    // Standard OTLP HTTP/JSON and protobuf, plus gRPC. ACK is durable staging.
    net::io_context io;tcp::acceptor port1(io,{tcp::v4(),0}),port2(io,{tcp::v4(),0});auto hp=port1.local_endpoint().port(),gp=port2.local_endpoint().port();port1.close();port2.close();
    env("TRACE_MODE","external");env("SOURCES_OTEL_HTTP_PORT",std::to_string(hp));env("SOURCES_OTEL_GRPC_PORT",std::to_string(gp));env("SOURCES_OTEL_BEARER_TOKEN","exporter-token");env("SOURCES_OTEL_MAX_BODY_BYTES","2048");env("SINKS_TRACE_MAX_PENDING","1");config();assert(!CObject::trace_enabled);
    auto expanded=request;
    auto* bytes=expanded.mutable_resource_spans(0)->mutable_scope_spans(0)->mutable_spans(0)->add_attributes();
    bytes->set_key("binary.evidence");bytes->mutable_value()->set_bytes_value(std::string(1400,'x'));
    assert(expanded.ByteSizeLong()<2048);
    auto expanded_json=otlpJson(expanded);assert(expanded_json.size()>2048);
    assert(decodeOtlp(expanded.SerializeAsString(),false,decoded,error));
    assert(!decodeOtlp(expanded_json,true,decoded,error));
    assert(decodeOtlp(expanded_json,true,decoded,error,33554432));
    assert(traceDelivery.Open());OtlpReceiver receiver;assert(receiver.Open());std::thread listener([&]{receiver.Go();});
    auto post=[&](const std::string& data,const std::string& type,const std::string& token){return bounded_http::request(false,"127.0.0.1",std::to_string(hp),"/v1/traces","POST",data,token,{},type,2s);};
    assert(post(body,"application/json","Bearer wrong").result_int()==401);
    assert(post(body,"application/json","Bearer exporter-token").result_int()==200);
    assert(files(base,"incoming")==1);
    assert(post(request.SerializeAsString(),"application/x-protobuf","Bearer exporter-token").result_int()==200);
    assert(post("not protobuf","application/x-protobuf","Bearer exporter-token").result_int()==400);
    auto compressed=bounded_http::request(false,"127.0.0.1",std::to_string(hp),"/v1/traces","POST",gzip(body),"Bearer exporter-token",{{"Content-Encoding","gzip"}},"application/json",2s);
    assert(compressed.result_int()==200);
    auto oversized=bounded_http::request(false,"127.0.0.1",std::to_string(hp),"/v1/traces","POST",gzip(std::string(10000,'x')),"Bearer exporter-token",{{"Content-Encoding","gzip"}},"application/json",2s);
    assert(oversized.result_int()==413);
    auto another=request;another.mutable_resource_spans(0)->mutable_scope_spans(0)->mutable_spans(0)->set_span_id(std::string(8,'z'));
    assert(post(otlpJson(another),"application/json","Bearer exporter-token").result_int()==503);
    auto stub=opentelemetry::proto::collector::trace::v1::TraceService::NewStub(grpc::CreateChannel("127.0.0.1:"+std::to_string(gp),grpc::InsecureChannelCredentials()));
    grpc::ClientContext context;context.AddMetadata("authorization","Bearer exporter-token");context.set_deadline(std::chrono::system_clock::now()+2s);
    opentelemetry::proto::collector::trace::v1::ExportTraceServiceResponse response;assert(stub->Export(&context,request,&response).ok());
    // The same spans exported over different transports share one immutable inbox record.
    assert(files(base,"incoming")==1);
    receiver.Close();listener.join();assert(!receiver.HasFailed());
    env("SINKS_TRACE_MAX_PENDING","4096");config();
    traceDelivery.Close();assert(traceDelivery.Open());assert(files(base,"incoming")==1);
    af.status=201;Trace traceWorker;TraceIntegrationTest::patterns(traceWorker);traceWorker.Go();
    assert(files(base,"incoming")==0);assert(files(base,"opensearch")>=1);assert(files(base,"alertflex")>=1);
    auto os_files=files(base,"opensearch"),af_files=files(base,"alertflex");
    auto ordinary=sample();auto* span=ordinary.mutable_resource_spans(0)->mutable_scope_spans(0)->mutable_spans(0);
    span->set_span_id(std::string(8,'n'));span->clear_attributes();span->set_name("ordinary unmatched operation");
    assert(traceDelivery.incoming(otlpJson(ordinary)));traceWorker.Go();
    assert(files(base,"opensearch")==os_files+1);assert(files(base,"alertflex")==af_files);
    auto events=externalTraceEvents(request);TracePattern p;p.id="external-trigger";auto triggered=externalTriggeredTrace(events,p,"agent-external",events[0].ts);
    assert(decodeOtlp(triggered,true,decoded,error));assert(decoded.resource_spans(0).scope_spans(0).spans(0).span_id()==std::string(8,'s'));
    traceWorker.Close();traceDelivery.Close();
    env("TRACE_MODE","internal");config();assert(CObject::trace_enabled);assert(traceDelivery.Open());
    Trace internal;TraceEvent observed;observed.ts=events[0].ts;observed.agent_key="internal-agent";observed.request_id="http-unmatched";observed.track="HTTP";observed.url="/ordinary";
    assert(enqueueTraceEvent(q_proxy_trace,observed,"test"));os_files=files(base,"opensearch");internal.Go();
    assert(files(base,"opensearch")==os_files+1);assert(files(base,"alertflex")==af_files);internal.Close();traceDelivery.Close();
    env("TRACE_MODE","off");config();assert(!CObject::trace_enabled);Trace off;assert(!off.Open());
    std::string yaml_error;auto yaml=std::filesystem::path(__FILE__).parent_path().parent_path()/"etc/altprobe.yaml";assert(loadTraceConfig(1,yaml_error,yaml.string()));assert(traceConfig().mode=="internal");
    env("TRACE_MODE","invalid");assert(!loadTraceConfig(2,error));env("TRACE_MODE","internal");
    // Remove only the exact disposable fixture directory created by this process.
    assert(base.rfind("/tmp/altprobe-trace-test-",0)==0);std::filesystem::remove_all(base);
    std::cout<<"PASS durable trace recovery, OTLP HTTP/protobuf/gRPC, trigger routing and HTTP endpoint pipeline\n";
}
