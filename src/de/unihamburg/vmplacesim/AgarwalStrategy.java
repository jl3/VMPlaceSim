// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.Random;

/**
 * Implements the PCUF strategy proposed by Agarwal and Duong (Amit Agarwal and Ta Nguyen Binh Duong. 2019. Secure
 * virtual machine placement in cloud data centers. Future Gener. Comput. Syst. 100 (2019), pp. 210–222.).
 *
 * @author Jens Lindemann
 */
public class AgarwalStrategy extends PlacementStrategy {

    public AgarwalStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, true, false);
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        Subscription sub = vm.getSubscription();

        ArrayList<Host> eligibleHosts = new ArrayList<Host>();
        if(sub.getTotalVMs().size() > 0) { // not a new Subscription
            for(Host h : _activeHosts) {
                if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                    boolean seenAllSubs = true;
                    for(VM hostvm : h.getCurrentVMs()) {
                        Subscription hostsub = hostvm.getSubscription();
                        if(!sub.hasSeenSubscription(hostsub)) {
                            seenAllSubs = false;
                            break;
                        }
                    }

                    if(seenAllSubs) {
                        eligibleHosts.add(h);
                    }
                }
            }

            if(eligibleHosts.isEmpty()) {
                return pickEmptyHost(vm);
            } else {
                // find Host(s) with lowest number of free cores
                ArrayList<Host> fewestCoresAvailableHosts = new ArrayList<Host>();
                int fewestCoresAvailable = Integer.MAX_VALUE;

                for(Host h : eligibleHosts) {
                    int freeCores = h.freeCores();
                    if(freeCores < fewestCoresAvailable) {
                        fewestCoresAvailable = freeCores;
                        fewestCoresAvailableHosts = new ArrayList<Host>();
                        fewestCoresAvailableHosts.add(h);
                    } else if(freeCores == fewestCoresAvailable) {
                        fewestCoresAvailableHosts.add(h);
                    } // else ignore it
                }

                return pickRandomHost(fewestCoresAvailableHosts);
            }
        } else { // new Subscription
            for(Host h : _activeHosts) {
                if ((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                    eligibleHosts.add(h);
                }
            }

            if (eligibleHosts.isEmpty()) {
                return pickEmptyHost(vm);
            } else {
                return pickRandomHost(eligibleHosts);
            }
        }
    }
}
