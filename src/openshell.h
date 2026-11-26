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

#ifndef ALTPROBE_OPENSHELL_H
#define ALTPROBE_OPENSHELL_H
#include "ids_source.h"
#include "detection.h"

// OpenShell exports native OCSF 1.8.0 JSONL. Altprobe must not re-create or
// downgrade those records: it forwards the original object to the configured
// sinks and never re-correlates it locally.
class Openshell : public IdsSource {
public:
    Openshell() : IdsSource("openshell") {}
    bool processLine(const std::string& line) override;
};

#endif
