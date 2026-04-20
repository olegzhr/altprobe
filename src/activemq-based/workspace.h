/*
 *   Copyright 2021 Oleg Zharkov
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

#ifndef WORKSPACE_H
#define WORKSPACE_H

#include <string>
#include "main.h"

using namespace std;

bool EnsureDirectoryExists(const string& path);
bool IsDirectoryEmpty(const string& path);
bool IsDirectory(const string& path);
bool IsWritableDirectory(const string& path);
void ClearWorkspace(const string& path);

void EnsureTrailingSlash(string& str);
string CombinePaths(const string& a, const string& b);
bool PathExists(const string& path);
bool CreateDirectory(const string& path);

#endif /* WORKSPACE_H */

