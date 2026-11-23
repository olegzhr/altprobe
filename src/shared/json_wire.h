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

#ifndef ALTPROBE_JSON_WIRE_H
#define ALTPROBE_JSON_WIRE_H
#include "bounded_json.h"
#include <algorithm>

// JSON wire serialization. canonicalJson() is intentionally a typed comparison
// key and must not be used for HTTP or persisted OTLP payloads.
inline std::string jsonQuote(const std::string& value) {
    const char* hex="0123456789abcdef";std::string out="\"";
    for(unsigned char c:value){
        if(c=='"'||c=='\\'){out+='\\';out+=c;}
        else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
        else out+=c;
    }
    return out+'"';
}
inline std::string wireJson(const Json& value) {
    if(value.kind=='s')return jsonQuote(value.text);
    if(value.kind=='d'||value.kind=='b')return value.text;
    if(value.kind!='o'&&value.kind!='a')return "null";
    bool object=value.kind=='o';std::vector<const std::pair<std::string,Json>*> children;
    for(const auto& child:value.children)children.push_back(&child);
    if(object)std::sort(children.begin(),children.end(),[](const auto* a,const auto* b){return a->first<b->first;});
    std::string out=object?"{":"[";bool first=true;
    for(const auto* child:children){if(!first)out+=',';first=false;if(object)out+=jsonQuote(child->first)+":";out+=wireJson(child->second);}
    return out+(object?"}":"]");
}
#endif
