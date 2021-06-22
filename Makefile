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

.PHONY: build install inttest lint test

default: build

build:
	./build.sh

inttest:
	go test ./... -count=1 -tags integration

install:
	go build;
	cd cmd/hvclient; go install

lint:
	go vet ./...
	golint -set_exit_status -min_confidence=0.21 ./...
	golangci-lint run --exclude SA1019

test:
	go test ./... -count=1
