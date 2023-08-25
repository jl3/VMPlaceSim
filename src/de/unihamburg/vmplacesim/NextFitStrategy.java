// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.Random;

/**
 * Implements the next-fit bin packing heuristic for VM placement.
 *
 * @author Jens Lindemann
 */
public class NextFitStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;

    private int _lastChosenHostIndex;

    public NextFitStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, false, false);

        _lastChosenHostIndex = _hosts.length-1;
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        for (int i = 0; i < _hosts.length; i++) {
            int idx = (i+1+_lastChosenHostIndex)%_hosts.length;
            Host h = _hosts[idx];
            if ((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                _lastChosenHostIndex = idx;
                return h;
            }
        }

        return null; // No host with sufficient capacity.
    }
}
