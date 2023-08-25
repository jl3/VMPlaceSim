// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.Random;

/**
 * Implements the first-fit bin packing heuristic for VM placement.
 *
 * @author Jens Lindemann
 */
public class FirstFitStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;

    public FirstFitStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, false, false);
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        for (int i = 0; i < _hosts.length; i++) {
            Host h = _hosts[i];
            if ((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                return h;
            }
        }

        return null; // No host with sufficient capacity.
    }
}
