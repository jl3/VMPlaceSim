// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.Random;

/**
 * Implements the random-active strategy for VM placement. This strategy chooses a random active server with sufficient
 * free resources.
 *
 * @author Jens Lindemann
 */
public class RandomActiveStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;

    public RandomActiveStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets) {
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
        for(Host h : _activeHosts) {
            if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                    eligibleHosts.add(h);
            }
        }

        if(eligibleHosts.isEmpty()) {
            return pickEmptyHost(vm);
        } else {
            return pickRandomHost(eligibleHosts);
        }
    }
}
