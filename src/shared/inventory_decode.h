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

#pragma once
#include "inventory_types.h"
// Throws on invalid/ambiguous snapshots. The caller commits only after success.
void decodeInventory(const std::string& response, const std::string& asset,
    const std::string& project, bool include_credentials,
    PolicyInventory& candidate, bool& has_patterns);
