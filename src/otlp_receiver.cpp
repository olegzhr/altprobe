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

#include "otlp_receiver.h"
#include "trace_config.h"
#include "trace_delivery.h"
#include "otlp.h"
#include "helpers.h"
#include "opentelemetry/proto/collector/trace/v1/trace_service.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <grpcpp/resource_quota.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <openssl/crypto.h>
#include <zlib.h>
#include <thread>
#include <type_traits>

namespace {
namespace net=boost::asio;namespace beast=boost::beast;namespace http=beast::http;namespace ssl=net::ssl;
using tcp=net::ip::tcp;using Plain=beast::tcp_stream;using Secure=beast::ssl_stream<beast::tcp_stream>;
bool authorized(const std::string& value) {
    const auto& token=traceConfig().bearer_token;
    if(token.empty())return true;
    auto expected="Bearer "+token;
    return expected.size()==value.size() && CRYPTO_memcmp(expected.data(),value.data(),value.size())==0;
}
std::string peerAddress(const std::string& peer) {
    auto start=peer.find(':');if(start==std::string::npos)return "";
    auto value=peer.substr(start+1);
    if(!value.empty()&&value[0]=='[') {auto end=value.find(']');return end==std::string::npos?"":value.substr(1,end-1);}
    auto end=value.rfind(':');return end==std::string::npos?"":value.substr(0,end);
}
bool gunzip(const std::string& input,std::string& output,size_t limit) {
    z_stream stream{};stream.next_in=reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));stream.avail_in=input.size();
    if(inflateInit2(&stream,16+MAX_WBITS)!=Z_OK)return false;
    int result=Z_OK;char chunk[16384];
    while(result==Z_OK) {
        stream.next_out=reinterpret_cast<Bytef*>(chunk);stream.avail_out=sizeof(chunk);result=inflate(&stream,Z_NO_FLUSH);
        auto size=sizeof(chunk)-stream.avail_out;
        if(output.size()+size>limit) {output.resize(limit+1);inflateEnd(&stream);return false;}
        output.append(chunk,size);
    }
    bool okay=result==Z_STREAM_END&&stream.avail_in==0;inflateEnd(&stream);return okay;
}
// google.rpc.Status: field 2 is the UTF-8 developer-facing message.
std::string protobufError(const std::string& message) {
    std::string body(1,'\x12');size_t n=message.size();
    while(n>127){body+=static_cast<char>((n&127)|128);n>>=7;}body+=static_cast<char>(n);return body+message;
}
bool stage(const OtlpRequest& request) {
    if(request.resource_spans().empty())return true;
    return traceDelivery.incoming(otlpJson(request));
}
class TraceService final:public opentelemetry::proto::collector::trace::v1::TraceService::Service {
    std::atomic<unsigned> running{0};
    grpc::Status Export(grpc::ServerContext* context,const OtlpRequest* input,
        opentelemetry::proto::collector::trace::v1::ExportTraceServiceResponse*) override {
        auto count=running.fetch_add(1);struct Release{std::atomic<unsigned>& n;~Release(){--n;}}release{running};
        const auto& c=traceConfig().collector;
        if(!listenerPeerAllowed(peerAddress(context->peer()),c))return {grpc::StatusCode::PERMISSION_DENIED,"untrusted exporter"};
        auto auth=context->client_metadata().find("authorization");
        std::string value=auth==context->client_metadata().end()?"":std::string(auth->second.data(),auth->second.size());
        if(!authorized(value))return {grpc::StatusCode::UNAUTHENTICATED,"invalid collector credentials"};
        if(context->IsCancelled())return {grpc::StatusCode::CANCELLED,"cancelled"};
        if(count>=static_cast<unsigned>(c.max_requests))return {grpc::StatusCode::UNAVAILABLE,"collector busy"};
        std::string error;
        if(!validateOtlp(*input,error))return {grpc::StatusCode::INVALID_ARGUMENT,error};
        try{if(stage(*input))return grpc::Status::OK;}catch(...){}
        return {grpc::StatusCode::UNAVAILABLE,"durable trace spool unavailable or full"};
    }
};
template<class Stream> class Session:public std::enable_shared_from_this<Session<Stream>> {
    Stream stream;beast::flat_buffer buffer;http::request_parser<http::string_body> parser;http::response<http::string_body> response;
    std::shared_ptr<std::atomic<unsigned>> running;std::shared_ptr<ssl::context> tls;
    bool json=true;
public:
    template<class... Args> Session(std::shared_ptr<std::atomic<unsigned>> n,std::shared_ptr<ssl::context> t,Args&&... args)
        :stream(std::forward<Args>(args)...),buffer(traceConfig().collector.max_body_bytes+16384),running(std::move(n)),tls(std::move(t)) {
        parser.body_limit(traceConfig().collector.max_body_bytes);parser.header_limit(8192);
    }
    ~Session(){--*running;}
    void start(){
        beast::get_lowest_layer(stream).expires_after(std::chrono::milliseconds(traceConfig().collector.request_timeout_ms));
        if constexpr(std::is_same<Stream,Secure>::value){auto self=this->shared_from_this();stream.async_handshake(ssl::stream_base::server,[self](beast::error_code ec){if(!ec)self->read();});}
        else read();
    }
private:
    void read(){
        beast::get_lowest_layer(stream).expires_after(std::chrono::milliseconds(traceConfig().collector.request_timeout_ms));
        auto self=this->shared_from_this();http::async_read(stream,buffer,parser,[self](beast::error_code ec,size_t){
            if(!ec)self->receive();else if(ec==http::error::body_limit||ec==http::error::header_limit)self->send(413,"request too large");
        });
    }
    void receive(){
        try{
            const auto& r=parser.get();
            auto type=std::string(r[http::field::content_type]);type=type.substr(0,type.find(';'));
            json=type!="application/x-protobuf";
            if(r.method()!=http::verb::post||r.target()!="/v1/traces"){send(404,"unknown OTLP path");return;}
            if(!authorized(std::string(r[http::field::authorization]))){send(401,"invalid collector credentials");return;}
            if(type!="application/json"&&type!="application/x-protobuf"){send(415,"expected OTLP JSON or protobuf");return;}
            auto encoding=std::string(r[http::field::content_encoding]);std::string body=r.body();
            if(encoding=="gzip"){
                std::string expanded;
                if(!gunzip(body,expanded,traceConfig().collector.max_body_bytes)){send(expanded.size()>static_cast<size_t>(traceConfig().collector.max_body_bytes)?413:400,"invalid or oversized gzip body");return;}
                body=std::move(expanded);
            }else if(!encoding.empty()&&encoding!="identity"){send(415,"unsupported compression");return;}
            OtlpRequest request;std::string error;
            if(!decodeOtlp(body,json,request,error)){send(400,error);return;}
            if(!stage(request)){send(503,"durable trace spool unavailable or full");return;}
            send(200,""); // ACK only after durable staging, before any downstream I/O.
        }catch(...){send(503,"collector unavailable");}
    }
    void send(unsigned status,const std::string& message){
        response.version(11);response.result(status);response.keep_alive(false);
        response.set(http::field::content_type,json?"application/json":"application/x-protobuf");
        response.set(http::field::server,"altprobe-otlp");
        response.body()=status==200?(json?"{}":""):(json?"{\"message\":\""+escapeJsonString(message)+"\"}":protobufError(message));
        if(status==503)response.set(http::field::retry_after,"1");response.prepare_payload();
        beast::get_lowest_layer(stream).expires_after(std::chrono::milliseconds(traceConfig().collector.request_timeout_ms));
        auto self=this->shared_from_this();http::async_write(stream,response,[self](beast::error_code,size_t){
            beast::error_code ignored;beast::get_lowest_layer(self->stream).socket().close(ignored);
        });
    }
};
}
struct OtlpReceiver::Impl {
    net::io_context ioc;tcp::acceptor acceptor{net::make_strand(ioc)};
    std::shared_ptr<ssl::context> tls;
    std::shared_ptr<std::atomic<unsigned>> running=std::make_shared<std::atomic<unsigned>>(0);
    TraceService service;std::unique_ptr<grpc::Server> grpc;
    std::atomic<bool> stopped{false},failed{false};std::mutex lifecycle;bool started=false;
    void accept(){
        acceptor.async_accept(net::make_strand(ioc),[this](beast::error_code ec,tcp::socket socket){
            if(ec&&!stopped&&ec!=net::error::operation_aborted){failed=true;ioc.stop();return;}
            if(!ec&&!stopped){
                beast::error_code error;auto peer=socket.remote_endpoint(error);const auto& c=traceConfig().collector;
                if(!error&&listenerPeerAllowed(peer.address().to_string(),c)){
                    unsigned count=running->fetch_add(1);
                    if(count<static_cast<unsigned>(c.max_requests)){
                        bool built=false;
                        try{
                            if(tls){auto s=std::make_shared<Session<Secure>>(running,tls,std::move(socket),*tls);built=true;s->start();}
                            else{auto s=std::make_shared<Session<Plain>>(running,tls,std::move(socket));built=true;s->start();}
                        }catch(...){if(!built)--*running;}
                    }else --*running;
                }
            }
            if(!stopped&&acceptor.is_open())accept();
        });
    }
};
OtlpReceiver::OtlpReceiver():impl_(new Impl){}
OtlpReceiver::~OtlpReceiver(){Close();}
bool OtlpReceiver::Open(){
    if(traceConfig().mode!="external"){RequestStop();return false;}
    try{
        const auto& t=traceConfig();const auto& c=t.collector;
        if(!traceDelivery.ready())throw std::runtime_error("spool not ready");
        if(t.http_port){
            if(!c.tls_cert.empty()){
                impl_->tls=std::make_shared<ssl::context>(ssl::context::tls_server);
                impl_->tls->set_options(ssl::context::default_workarounds|ssl::context::no_sslv2|ssl::context::no_sslv3|ssl::context::no_tlsv1|ssl::context::no_tlsv1_1);
                impl_->tls->use_certificate_chain_file(c.tls_cert);impl_->tls->use_private_key_file(c.tls_key,ssl::context::pem);
                if(!c.tls_ca.empty()){impl_->tls->load_verify_file(c.tls_ca);impl_->tls->set_verify_mode(ssl::verify_peer|ssl::verify_fail_if_no_peer_cert);}
            }
            tcp::endpoint e(net::ip::make_address(c.bind_host),t.http_port);
            impl_->acceptor.open(e.protocol());impl_->acceptor.set_option(net::socket_base::reuse_address(true));impl_->acceptor.bind(e);impl_->acceptor.listen();impl_->accept();
        }
        if(t.grpc_port){
            grpc::ServerBuilder builder;std::shared_ptr<grpc::ServerCredentials> credentials;
            if(c.tls_cert.empty())credentials=grpc::InsecureServerCredentials();
            else{
                grpc::SslServerCredentialsOptions options;options.pem_key_cert_pairs.push_back({listenerReadFile(c.tls_key),listenerReadFile(c.tls_cert)});
                if(!c.tls_ca.empty()){options.pem_root_certs=listenerReadFile(c.tls_ca);options.client_certificate_request=GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;}
                credentials=grpc::SslServerCredentials(options);
            }
            auto host=c.bind_host.find(':')==std::string::npos?c.bind_host:"["+c.bind_host+"]";
            int selected=0;builder.AddListeningPort(host+":"+std::to_string(t.grpc_port),credentials,&selected);
            builder.RegisterService(&impl_->service);builder.SetMaxReceiveMessageSize(c.max_body_bytes);builder.SetMaxSendMessageSize(65536);
            grpc::ResourceQuota quota;quota.Resize(67108864);quota.SetMaxThreads(c.workers+2);builder.SetResourceQuota(quota);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS,1);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MIN_POLLERS,1);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS,c.workers);
            impl_->grpc=builder.BuildAndStart();if(!impl_->grpc||selected!=t.grpc_port)throw std::runtime_error("gRPC bind failed");
        }
        source_status=true;return true;
    }catch(...){Close();CObject::SysLog(const_cast<char*>("[OTLP] listener startup failed"));return false;}
}
bool OtlpReceiver::Go(){
    {std::lock_guard<std::mutex> lock(impl_->lifecycle);impl_->started=true;}
    std::vector<std::thread> workers;
    try{
        if(impl_->grpc)workers.emplace_back([this]{impl_->grpc->Wait();if(!impl_->stopped){impl_->failed=true;impl_->ioc.stop();}});
        if(traceConfig().http_port){for(int i=1;i<traceConfig().collector.workers;++i)workers.emplace_back([this]{try{impl_->ioc.run();}catch(...){impl_->failed=true;impl_->ioc.stop();}});impl_->ioc.run();}
        else while(source_status&&!impl_->failed)WaitForStop(std::chrono::milliseconds(100));
    }catch(...){impl_->failed=true;}
    if(!impl_->stopped){impl_->failed=true;Close();}
    for(auto& worker:workers)worker.join();return false;
}
void OtlpReceiver::Close(){
    RequestStop();if(!impl_||impl_->stopped.exchange(true))return;
    if(impl_->grpc)impl_->grpc->Shutdown(std::chrono::system_clock::now()+std::chrono::milliseconds(500));
    std::lock_guard<std::mutex> lock(impl_->lifecycle);
    if(impl_->started)net::post(impl_->acceptor.get_executor(),[this]{beast::error_code e;impl_->acceptor.close(e);impl_->ioc.stop();});
    else{beast::error_code e;impl_->acceptor.close(e);impl_->ioc.stop();}
}
bool OtlpReceiver::HasFailed()const{return impl_->failed;}
