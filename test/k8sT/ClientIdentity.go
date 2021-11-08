// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sTest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strings"

	external_ips "github.com/cilium/cilium/test/k8sT/manifests/externalIPs"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
)

var _ = Describe("K8sClientIdentity", func() {
	var (
		kubectl           *helpers.Kubectl
		ciliumFilename    string
		simpleHTTPServer  string
		simpleHTTPService string
		cnpClientIdentity string
		err               error
		secondaryK8s1IPv4 string
		webAppPort        string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		simpleHTTPServer = helpers.ManifestGet(kubectl.BasePath(), "simple-http-test-server.yaml")
		simpleHTTPService = helpers.ManifestGet(kubectl.BasePath(), "simple-http-test-service.yaml")
		cnpClientIdentity = helpers.ManifestGet(kubectl.BasePath(), "client-identity.yaml")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		kubectl.Apply(helpers.ApplyOptions{FilePath: simpleHTTPServer, Namespace: helpers.DefaultNamespace}).ExpectSuccess("could not create resource.")
		kubectl.Apply(helpers.ApplyOptions{FilePath: simpleHTTPService, Namespace: helpers.DefaultNamespace}).ExpectSuccess("could not create resource.")

		err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l component=webserver", helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "pods are not ready after timeout")

		k8s1NodeName, _ := kubectl.GetNodeInfo(helpers.K8s1)
		secondaryK8s1IPv4 = getIPv4AddrForIface(kubectl, k8s1NodeName, external_ips.PublicInterfaceName)
		webAppPort = "30000"
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium endpoint list")
	})

	AfterAll(func() {
		kubectl.Delete(simpleHTTPServer)
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	It("Indentity verification with JWT tokens", func() {

		By("Sending request to webserver *BEFORE* apply client identity CNP")
		err = sendWeserverSimpleRequestFromOutside(secondaryK8s1IPv4, webAppPort, "")
		Expect(err).Should(BeNil(), "cannot send request to webserver on %s:%s", secondaryK8s1IPv4, webAppPort)

		By("Applying client identity CNP")
		_, err = kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, cnpClientIdentity, helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "cannot install policy %s", cnpClientIdentity)

		By("Sending request to webserver *AFTER* apply client identity CNP")
		err = sendWeserverSimpleRequestFromOutside(secondaryK8s1IPv4, webAppPort, "")
		Expect(err).ShouldNot(BeNil(), "request unexpectedly accepted by %s:%s while it should not.", secondaryK8s1IPv4, webAppPort)

		By("Sending request to webserver *AFTER* apply client identity policy with *INVALID* jwt token")
		err = sendWeserverSimpleRequestFromOutside(secondaryK8s1IPv4, webAppPort,
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkZUcVRqREU4NHE5M2lFR0s1YmpZQyJ9.eyJpc3MiOiJodHRwczovL2Rldi04YXMyaWpmNS51cy5hdXRoMC5jb20vIiwic3ViIjoiZUtjeHlNMGJOZXB5R0MyZThzMnBQQ1BJRldYcVE1bVNAY2xpZW50cyIsImF1ZCI6InRoYWxlcy1hY2N1a25veC0xc3QiLCJpYXQiOjE2MzQyNDU0MTcsImV4cCI6MTYzNDMzMTgxNywiYXpwIjoiZUtjeHlNMGJOZXB5R0MyZThzMnBQQ1BJRldYcVE1bVMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.gCeXZkA4luHYRGhSW3IjMHpeMDsUC1xEm71PBUzdidnB_-r940FX_HOJ3AAg14NfN-OphzkoibYdaxChe08HPVO9zPwjmffEBCRArI96JdyjoXDA6txhoJeKsa_M6LfyKpijE1d9ByLdAMyHLLdDSlTS0mSaZeX7m3Cu-RdsUIHuOUIGaWjgG2MkMtUhQWULm5sxgFIbWgkj6f0QD_ncpQlEPkMJn76GQPeFv4cgagF9wutPmVw4ajOqe1L0vdKervsCsbUe2qneaiytHgk57zySkLVUcVN_HeCxKWNBW9vvTNEhJVsrt2QYOsLLfwAdZLT9z9XUVEOLUVHgyUkbGg")
		Expect(err).ShouldNot(BeNil(), "request unexpectedly accepted by %s:%s while it should not.", secondaryK8s1IPv4, webAppPort)

		By("Sending request to webserver *AFTER* apply client identity policy with *VALID* jwt token")
		err = sendWeserverSimpleRequestFromOutside(secondaryK8s1IPv4, webAppPort, getAccessToken())
		Expect(err).Should(BeNil(), "request unexpectedly reject by %s:%s while it should accept.", secondaryK8s1IPv4, webAppPort)
	})
})

func sendWeserverSimpleRequestFromOutside(nodeIp string, appPort string, token string) error {
	var cmd string

	if token != "" {
		cmd = "--request GET --url " + nodeIp + ":" + appPort + " --header " + "'authorization: Bearer " + token + "'"
	} else {
		cmd = "--request GET --url " + nodeIp + ":" + appPort
	}

	curl := helpers.CurlWithRetries(cmd, 1, false)
	logger.Infof("Executing curl with arguments: %s", curl)

	out, err := exec.Command(
		"/bin/bash", "-c",
		curl).CombinedOutput()

	if !strings.Contains(string(out), "200 OK") {
		err = errors.New("request not authorized")
	}

	logger.Infof(string(out))

	return err
}

func getAccessToken() string {
	// using a test account for indentity provider
	// no real application running behind the API
	// secrets can be  exposed without concerning
	url := "https://dev-8as2ijf5.us.auth0.com/oauth/token"
	payload := strings.NewReader("{\"client_id\":\"5dPh3k4LMXM9hfb911CeKZLV8JF5Tumf\",\"client_secret\":\"7-uuvjGiF1WrHZVJ457n-OcM6gl5R9DvSsjAdZLK1Tm86smris8zEItePIqxyuLm\",\"audience\":\"thales-accuknox-2nd\",\"grant_type\":\"client_credentials\"}")

	req, err := http.NewRequest("POST", url, payload)

	if err != nil {
		log.Fatalln(err)
		return ""
	}

	req.Header.Add("content-type", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)

	a := make(map[string]string)

	json.Unmarshal([]byte(body), &a)

	fmt.Println(a["access_token"])

	return a["access_token"]
}
