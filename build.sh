#!/bin/bash

# Copyright (c) 2019-2021 GMO GlobalSign Pte. Ltd.
# 
# Licensed under the MIT License (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
# 
# https://opensource.org/licenses/MIT
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Check, build, test the hvclient. 
gofumports -d ./. &&
golint ./... &&
go build ./... &&
go test || {
    echo "hvclient build failed" 1>&2
    exit 1
}
