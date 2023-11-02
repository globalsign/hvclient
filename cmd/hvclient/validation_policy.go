/*
Copyright (c) 2019-2021 GMO GlobalSign Pte. Ltd.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/globalsign/hvclient"
)

// validationPolicy outputs the validation policy in JSON format.
func validationPolicy(clnt *hvclient.Client) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var pol, err = clnt.Policy(ctx)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var data []byte
	if data, err = json.MarshalIndent(pol, "", "   "); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s\n", string(data))
}
