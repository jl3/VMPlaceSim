// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;

/**
 * Implements the placement strategy proposed by Azar et al.
 *
 * @author Jens Lindemann
 */
public class AzarStrategy extends PlacementStrategy {
    protected HashSet<Host> _fullHosts;

    private double _maxMemory;
    private int _maxCores;

    private int _numActiveHosts;

    public AzarStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maxCores, double maxMemory, int maliciousSets) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, false, false);
        _numActiveHosts = activeHosts;

        _maxCores = maxCores;
        _maxMemory = maxMemory;
        _fullHosts = new HashSet<Host>();
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        if(!((vm.getCores() > _maxCores) || (vm.getMemory() > _maxMemory))) {
            // This is the default case, where the assumption Azar et al. made as to the maximum size of a VM
            // (smaller than half a host's capacity) holds.

            return pickRandomHost(_activeHosts);
        } else {
            // The 2019 dataset contains VMs with 24 cores. If we keep the Host capacity at 32 cores (as in the
            // experiments by Agarwal et al.), Azar et al's assumption no longer holds. To avoid having to close
            // Hosts to VMs after just 9 cores are busy or changing Host capacity, there needs to be special
            // treatment for such VMs.
            // Note that this may mean that fewer Hosts than intended will be eligible to host a large VM.
            // To make up for this, the VM may instead be placed on an inactive empty Host.

            ArrayList<Host> eligibleHosts = new ArrayList<Host>();
            for(Host h : _activeHosts) {
                // check Host capacity, add to eligibleHosts if capacity sufficient
                if(h.freeCores() >= vm.getCores() && h.freeMemory() >= vm.getMemory()) {
                    eligibleHosts.add(h);
                }
            }

            if(!eligibleHosts.isEmpty()) {
                // To remain within the spirit of Azar's algorithm, we will check how many Hosts have sufficient
                // capacity to host the new VM. If this is lower than the number of Hosts that should be open to
                // new VMs, the VM will instead be deployed to an inactive empty Host with an appropriate chance, so
                // that there is still a sufficient number of open Hosts. The only exception to this is where all Hosts
                // are already active.

                if(_rnd.nextInt(_numActiveHosts) < eligibleHosts.size() || _inactiveHosts.size() == 0) {
                    return pickRandomHost(eligibleHosts);
                } else {
                    return this.activateHost();
                }
            } else {
                return this.activateHost();
            }
        }
    }

    @Override
    protected void createVM(VM vm, Host host) {
        super.createVM(vm, host);

        if(host.freeMemory() < _maxMemory || host.freeCores() < _maxCores) {
            _activeHosts.remove(host);
            _fullHosts.add(host);

            // Activate an inactive Host to replace the one just filled up.
            this.activateHost();
        }
    }

    @Override
    protected void deleteVM(VM vm) {
        Host h = vm.getCurrentHost();
        boolean hostWasFull = h.freeCores() < _maxCores || h.freeMemory() < _maxMemory;

        super.deleteVM(vm, false);

        // If it was full, check again if Host is full
        // If no longer full: remove from _fullHosts, add to _activaHosts
        if(hostWasFull) {
            boolean hostIsFull = h.freeCores() < _maxCores || h.freeMemory() < _maxMemory;
            if(!hostIsFull) {
                _fullHosts.remove(h);
                _activeHosts.add(h);
            }
        }

        // Check if there are too many active Hosts. If so, try to find and shut down an empty Host.
        // Even if a full Host just reverted to an active one, there may not be too many active
        // Hosts if the algorithm previously ran out of Hosts with sufficient free capacity to
        // keep the desired number of Hosts active.
        int excessActiveHosts = _activeHosts.size() - _numActiveHosts;
        if(excessActiveHosts > 0) {
            deactivateEmptyHosts(excessActiveHosts);
        }
    }

    @Override
    protected void updateCoverageStats(int malSet) {
        int hostsAtDanger = 0;
        for(Host h : _activeHosts) {
            if(h.hasMaliciousVM(malSet)) {
                hostsAtDanger++;
            }
        }
        for(Host h : _fullHosts) {
            if(h.hasMaliciousVM(malSet)) {
                hostsAtDanger++;
            }
        }
        double coverage = (double) hostsAtDanger / (_activeHosts.size() + _fullHosts.size());
        _coverageStr[malSet] += coverage;
    }

    @Override
    protected int numberOfRunningHosts() {
        if(_fullHosts != null) {
            // This will happen during the call of the super constructor.
            return _activeHosts.size() + _fullHosts.size();
        } else {
            return _activeHosts.size();
        }
    }
}
