// Copyright 2016-2020 Authors of Cilium
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

package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	datapathIpcache "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// LocalConfig returns the local configuration of the daemon's nodediscovery.
func (d *Daemon) LocalConfig() *datapath.LocalNodeConfiguration {
	<-d.nodeDiscovery.LocalStateInitialized
	return &d.nodeDiscovery.LocalConfig
}

func (d *Daemon) createNodeConfigHeaderfile() error {
	nodeConfigPath := option.Config.GetNodeConfigPath()
	f, err := os.Create(nodeConfigPath)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to create node configuration file")
		return err
	}
	defer f.Close()

	if err = d.datapath.WriteNodeConfig(f, &d.nodeDiscovery.LocalConfig); err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to write node configuration file")
		return err
	}
	return nil
}

func deleteHostDevice() {
	link, err := netlink.LinkByName(option.Config.HostDevice)
	if err != nil {
		log.WithError(err).Warningf("Unable to lookup host device %s. No old cilium_host interface exists", option.Config.HostDevice)
		return
	}

	if err := netlink.LinkDel(link); err != nil {
		log.WithError(err).Errorf("Unable to delete host device %s to change allocation CIDR", option.Config.HostDevice)
	}
}

// listFilterIfs returns a map of interfaces based on the given filter.
// The filter should take a link and, if found, return the index of that
// interface, if not found return -1.
func listFilterIfs(filter func(netlink.Link) int) (map[int]netlink.Link, error) {
	ifs, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if idx := filter(intf); idx != -1 {
			vethLXCIdxs[idx] = intf
		}
	}
	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func clearCiliumVeths() error {
	log.Info("Removing stale endpoint interfaces")

	leftVeths, err := listFilterIfs(func(intf netlink.Link) int {
		// Filter by veth and return the index of the interface.
		if intf.Type() == "veth" {
			return intf.Attrs().Index
		}
		return -1
	})

	if err != nil {
		return fmt.Errorf("unable to retrieve host network interfaces: %s", err)
	}

	for _, v := range leftVeths {
		peerIndex := v.Attrs().ParentIndex
		parentVeth, found := leftVeths[peerIndex]
		if found && peerIndex != 0 && strings.HasPrefix(parentVeth.Attrs().Name, "lxc") {
			err := netlink.LinkDel(v)
			if err != nil {
				log.WithError(err).Warningf("Unable to delete stale veth device %s", v.Attrs().Name)
			}
		}
	}
	return nil
}

// SetPrefilter sets the preftiler for the given daemon.
func (d *Daemon) SetPrefilter(preFilter datapath.PreFilter) {
	d.preFilter = preFilter
}

// EndpointMapManager is a wrapper around an endpointmanager as well as the
// filesystem for removing maps related to endpoints from the filesystem.
type EndpointMapManager struct {
	*endpointmanager.EndpointManager
}

// RemoveDatapathMapping unlinks the endpointID from the global policy map, preventing
// packets that arrive on this node from being forwarded to the endpoint that
// used to exist with the specified ID.
func (e *EndpointMapManager) RemoveDatapathMapping(endpointID uint16) error {
	return policymap.RemoveGlobalMapping(uint32(endpointID))
}

// RemoveMapPath removes the specified path from the filesystem.
func (e *EndpointMapManager) RemoveMapPath(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

func endParallelMapMode() {
	ipcachemap.IPCache.EndParallelMode()
}

// syncLXCMap adds local host enties to bpf lxcmap, as well as
// ipcache, if needed, and also notifies the daemon and network policy
// hosts cache if changes were made.
func (d *Daemon) syncEndpointsAndHostIPs() error {
	if option.Config.DryMode {
		return nil
	}

	specialIdentities := []identity.IPIdentityPair{}

	if option.Config.EnableIPv4 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv4().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.GetReservedID(labels.IDNameHost),
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, net.IPv4len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	if option.Config.EnableIPv6 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv6().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv6 addresses")
		}

		addrs = append(addrs, node.GetIPv6Router())
		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.GetReservedID(labels.IDNameHost),
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, net.IPv6len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return err
	}

	var k8sMeta *ipcache.K8sMetadata
	for _, ipIDPair := range specialIdentities {
		hostKey := node.GetIPsecKeyIdentity()
		isHost := ipIDPair.ID == identity.GetReservedID(labels.IDNameHost)
		if isHost {
			added, err := lxcmap.SyncHostEntry(ipIDPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %s", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDPair.IP).Debugf("Added local ip to endpoint map")
			}

			if option.Config.ExternalWorkload {
				// Host IP address might have k8s metadata associated with it
				// when the agent is running in an External Workload.
				// Existing metadata should not be overwritten by the following Upsert() call.
				k8sMeta = ipcache.IPIdentityCache.GetK8sMetadata(ipIDPair.IP.String())
			}
		}

		delete(existingEndpoints, ipIDPair.IP.String())

		// Upsert will not propagate (reserved:foo->ID) mappings across the cluster,
		// and we specifically don't want to do so.
		ipcache.IPIdentityCache.Upsert(ipIDPair.PrefixString(), nil, hostKey, k8sMeta, ipcache.Identity{
			ID:     ipIDPair.ID,
			Source: source.Local,
		})
	}

	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr: hostIP,
				}).Warn("Unable to delete obsolete host IP from BPF map")
			} else {
				log.Debugf("Removed outdated host ip %s from endpoint map", hostIP)
			}

			ipcache.IPIdentityCache.Delete(hostIP, source.Local)
		}
	}

	return nil
}

// initMaps opens all BPF maps (and creates them if they do not exist). This
// must be done *before* any operations which read BPF maps, especially
// restoring endpoints and services.
func (d *Daemon) initMaps() error {
	if option.Config.DryMode {
		return nil
	}

	if _, err := lxcmap.LXCMap.OpenOrCreate(); err != nil {
		return err
	}

	// The ipcache is shared between endpoints. Parallel mode needs to be
	// used to allow existing endpoints that have not been regenerated yet
	// to continue using the existing ipcache until the endpoint is
	// regenerated for the first time. Existing endpoints are using a
	// policy map which is potentially out of sync as local identities are
	// re-allocated on startup. Parallel mode allows to continue using the
	// old version until regeneration. Note that the old version is not
	// updated with new identities. This is fine as any new identity
	// appearing would require a regeneration of the endpoint anyway in
	// order for the endpoint to gain the privilege of communication.
	if _, err := ipcachemap.IPCache.OpenParallel(); err != nil {
		return err
	}

	if err := metricsmap.Metrics.OpenOrCreate(); err != nil {
		return err
	}

	if _, err := tunnel.TunnelMap.OpenOrCreate(); err != nil {
		return err
	}

	if _, err := egressmap.EgressMap.OpenOrCreate(); err != nil {
		return err
	}

	pm := probes.NewProbeManager()
	supportedMapTypes := pm.GetMapTypes()
	createSockRevNatMaps := option.Config.EnableHostReachableServices &&
		option.Config.EnableHostServicesUDP && supportedMapTypes.HaveLruHashMapType
	if err := d.svc.InitMaps(option.Config.EnableIPv6, option.Config.EnableIPv4,
		createSockRevNatMaps, option.Config.RestoreState); err != nil {
		log.WithError(err).Fatal("Unable to initialize service maps")
	}

	possibleCPUs := common.GetNumPossibleCPUs(log)

	if err := eventsmap.InitMap(possibleCPUs); err != nil {
		return err
	}

	if err := signalmap.InitMap(possibleCPUs); err != nil {
		return err
	}

	if err := policymap.InitCallMap(); err != nil {
		return err
	}

	for _, ep := range d.endpointManager.GetEndpoints() {
		ep.InitMap()
	}

	for _, ep := range d.endpointManager.GetEndpoints() {
		if !ep.ConntrackLocal() {
			continue
		}
		for _, m := range ctmap.LocalMaps(ep, option.Config.EnableIPv4,
			option.Config.EnableIPv6) {
			if _, err := m.Create(); err != nil {
				return err
			}
		}
	}
	for _, m := range ctmap.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6) {
		if _, err := m.Create(); err != nil {
			return err
		}
	}

	ipv4Nat, ipv6Nat := nat.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6, option.Config.EnableNodePort)
	if ipv4Nat != nil {
		if _, err := ipv4Nat.Create(); err != nil {
			return err
		}
	}
	if ipv6Nat != nil {
		if _, err := ipv6Nat.Create(); err != nil {
			return err
		}
	}

	if option.Config.EnableNodePort {
		if err := neighborsmap.InitMaps(option.Config.EnableIPv4,
			option.Config.EnableIPv6); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv4FragmentsTracking {
		if err := fragmap.InitMap(option.Config.FragmentsMapEntries); err != nil {
			return err
		}
	}

	// Set up the list of IPCache listeners in the daemon, to be
	// used by syncEndpointsAndHostIPs()
	// xDS cache will be added later by calling AddListener(), but only if necessary.
	ipcache.IPIdentityCache.SetListeners([]ipcache.IPIdentityMappingListener{
		datapathIpcache.NewListener(d, d),
	})

	if option.Config.EnableIPv4 && option.Config.EnableIPMasqAgent {
		if _, err := ipmasq.IPMasq4Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	// Start the controller for periodic sync of the metrics map with
	// the prometheus server.
	controller.NewManager().UpdateController("metricsmap-bpf-prom-sync",
		controller.ControllerParams{
			DoFunc:      metricsmap.SyncMetricsMap,
			RunInterval: 5 * time.Second,
			Context:     d.ctx,
		})

	if !option.Config.RestoreState {
		// If we are not restoring state, all endpoints can be
		// deleted. Entries will be re-populated.
		lxcmap.LXCMap.DeleteAll()
	}

	if option.Config.EnableSessionAffinity {
		if _, err := lbmap.AffinityMatchMap.OpenOrCreate(); err != nil {
			return err
		}
		if option.Config.EnableIPv4 {
			if _, err := lbmap.Affinity4Map.OpenOrCreate(); err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 {
			if _, err := lbmap.Affinity6Map.OpenOrCreate(); err != nil {
				return err
			}
		}
	}

	if option.Config.EnableSVCSourceRangeCheck {
		if option.Config.EnableIPv4 {
			if _, err := lbmap.SourceRange4Map.OpenOrCreate(); err != nil {
				return err
			}
		}
		if option.Config.EnableIPv6 {
			if _, err := lbmap.SourceRange6Map.OpenOrCreate(); err != nil {
				return err
			}
		}
	}

	if option.Config.NodePortAlg == option.NodePortAlgMaglev {
		if err := lbmap.InitMaglevMaps(option.Config.EnableIPv4, option.Config.EnableIPv6, uint32(option.Config.MaglevTableSize)); err != nil {
			return err
		}
	}

	return nil
}

func setupIPSec() (int, uint8, error) {
	if !option.Config.EncryptNode {
		ipsec.DeleteIPsecEncryptRoute()
	}

	if !option.Config.EnableIPSec {
		return 0, 0, nil
	}

	authKeySize, spi, err := ipsec.LoadIPSecKeysFile(option.Config.IPSecKeyFile)
	if err != nil {
		return 0, 0, err
	}
	node.SetIPsecKeyIdentity(spi)
	return authKeySize, spi, nil
}

// Datapath returns a reference to the datapath implementation.
func (d *Daemon) Datapath() datapath.Datapath {
	return d.datapath
}
