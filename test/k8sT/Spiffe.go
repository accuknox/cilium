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

// - BDD Keywords: `Given`, `Context`, `It`
// - `Describe` will contain our specs like `Given`
// - `Context` will represet the `When`
// - `It` will represent the `Then it is ..`
// Ref: https://onsi.github.io/ginkgo/#documenting-complex-its-by

import (
	"context"
	"fmt"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

const (
	SpireNamespace                          = "spire"
	SpireServerLabel                        = "app=spire-server"
	SpireAgentLabel                         = "app=spire-agent"
	SpireScenario01Label                    = "app=spireScenario01"
	spiffeIdSADefaultNSDefault              = "spiffe://example.org/ns/default/sa/default"
	CmdCreateEntrySpireAgent                = "/opt/spire/bin/spire-server entry create -node -spiffeID spiffe://example.org/ns/spire/sa/spire-agent -selector k8s_sat:cluster:demo-cluster -selector k8s_sat:agent_ns:spire -selector k8s_sat:agent_sa:spire-agent"
	CmdCreateEntryCiliumAgent               = "/opt/spire/bin/spire-server entry create -spiffeID spiffe://example.org/ciliumagent -parentID spiffe://example.org/ns/spire/sa/spire-agent -selector unix:uid:0"
	CmdCreateEntryWorloadSADefaultNSDefault = "/opt/spire/bin/spire-server entry create -spiffeID spiffe://example.org/ns/default/sa/default -parentID spiffe://example.org/ns/spire/sa/spire-agent -selector k8s:ns:default -selector k8s:sa:default -ttl 60"
	CmdShowEntries                          = "/opt/spire/bin/spire-server entry show"
)

var _ = SkipDescribeIf(func() bool {
	return helpers.RunsOnGKE() || helpers.RunsOn419Kernel() || helpers.RunsOn54Kernel()
}, "K8sSpiffe", func() {
	Context("when a workload is deployed", func() {
		var (
			kubectl         *helpers.Kubectl
			ciliumFilename  string
			spire           string
			spireScenario01 string
		)

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"spiffe.enabled": "true",
			})

			_, err := kubectl.CiliumNodesWait()
			ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")

			By("making sure all endpoints are in ready state")
			err = kubectl.CiliumEndpointWaitReady()
			ExpectWithOffset(1, err).To(BeNil(), "Failure while waiting for all cilium endpoints to reach ready state")

			By("deploying spire components")
			spire = helpers.ManifestGet(kubectl.BasePath(), "spire.yaml")
			kubectl.ApplyDefault(spire).ExpectSuccess("Cannot import spire components")
			testNamespace := SpireNamespace

			By("making sure all spire components are in ready state")
			err = kubectl.WaitforPods(testNamespace, fmt.Sprintf("-l %s", SpireAgentLabel), helpers.HelperTimeout)
			Expect(err).Should(BeNil())
			err = kubectl.WaitforPods(testNamespace, fmt.Sprintf("-l %s", SpireServerLabel), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			spireScenario01 = helpers.ManifestGet(kubectl.BasePath(), "spire-scenario01.yaml")
			kubectl.ApplyDefault(spireScenario01).ExpectSuccess("Cannot import spire scenario 01 components")

			By("making sure all scenario01 are in ready state")
			err = kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", SpireScenario01Label), helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium endpoint list")
		})

		AfterAll(func() {
			kubectl.Delete(spireScenario01)
			kubectl.Delete(spire)
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
			kubectl.CloseSSHClient()
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		It("should assign a spiffe id label to it", func() {
			spireServerPod, _ := fetchPodsWithOffset(kubectl, SpireNamespace, "spire-server", SpireServerLabel, "", false, 0)
			kubectl.ExecPodCmd(SpireNamespace, spireServerPod, CmdCreateEntrySpireAgent)
			kubectl.ExecPodCmd(SpireNamespace, spireServerPod, CmdCreateEntryCiliumAgent)
			kubectl.ExecPodCmd(SpireNamespace, spireServerPod, CmdCreateEntryWorloadSADefaultNSDefault)
			// res := kubectl.CiliumEndpointsList(helpers.KubectlCmd + " get cilium -o jsonPath").WasSuccessful()

			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "Cannot determine cilium pod name")

			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, SpireScenario01Label)
			Expect(err).To(BeNil(), "Cannot get pods names")
			Expect(len(pods)).To(BeNumerically(">", 0), "No pods available to spire scenario 01")

			cmd := fmt.Sprintf("cilium endpoint get -l '%s'", spiffeIdSADefaultNSDefault)
			kubectl.CiliumExecUntilMatch(ciliumPodK8s1, cmd, spiffeIdSADefaultNSDefault)

			kubectl.CiliumExecContext(
				context.TODO(),
				ciliumPodK8s1,
				cmd,
			).ExpectSuccess()
		})

		// Context("when the a spiffe workload is allowed to communicate only with spiffe another spiffe workload", func() {
		// 	BeforeAll(func() {
		// 		cnpSpiffeAllowDefault := helpers.ManifestGet(kubectl.BasePath(), "cnp-spiffe-allow-sa-default-ns-default.yaml")
		// 		kubectl.ApplyDefault(cnpSpiffeAllowDefault).ExpectSuccess("Cannot import spiffe")
		// 	})
		// })
	})
})
