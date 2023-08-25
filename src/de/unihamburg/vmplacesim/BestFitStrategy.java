// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.Random;

/**
 * Implements the best-fit bin packing heuristic for VM placement.
 *
 * @author Jens Lindemann
 */
public class BestFitStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;

    public BestFitStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets) {
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
        for(Host h : _activeHosts) {
            if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {

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
