// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.Random;

/**
 * Implements the dedicated-instance strategy.
 *
 * @author Jens Lindemann
 */
public class DedicatedInstanceStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;

    public DedicatedInstanceStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, false, false);
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        ArrayList<Host> eligibleHosts = new ArrayList<Host>();
        int fewestCoresAvailable = Integer.MAX_VALUE;

        Host[] subhosts = vm.getSubscription().getCurrentHosts();

        for(Host h : subhosts) {
            if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                //VM[] hostvms = h.getCurrentVMs();
                ArrayList<VM> hostvms = h.getCurrentVMs();

                boolean allSameSub = true;
                for(VM hostvm : hostvms) {
                    if(!hostvm.getSubscription().equals(vm.getSubscription())) {
                        allSameSub = false;
                        break;
                    }
                }

                if(!allSameSub) {
                    continue;
                }

                int freeCores = h.freeCores();
                if(freeCores < fewestCoresAvailable) {
                    fewestCoresAvailable = freeCores;
                    eligibleHosts = new ArrayList<Host>();
                    eligibleHosts.add(h);
                } else if (freeCores == fewestCoresAvailable) {
                    eligibleHosts.add(h);
                } // else ignore
            }
        }

        if(eligibleHosts.isEmpty()) {
            return pickEmptyHost(vm);
        } else {
            return pickRandomHost(eligibleHosts);
        }
    }
}
