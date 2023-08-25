// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.Random;

/**
 * Implements the class of known-proportion placement strategies. This includes the known-user (KU) strategy
 * proposed in the paper, but can also be parameterised to instead implement a known-VM strategy (that did not turn
 * out to be better in preliminary experiments, though).
 *
 * @author Jens Lindemann
 */
public class KnownProportionStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;
    private boolean _lowestAvgSeenForNewSubs;

    public KnownProportionStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, boolean subscriptionBased, boolean lowestAvgSeenForNewSubs, int maliciousSets) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, true, false);
        _subscriptionBased = subscriptionBased;
        _lowestAvgSeenForNewSubs = lowestAvgSeenForNewSubs;
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
        double bestProportionKnown = 0;
        if(sub.getTotalVMs().size() > 0) { // not a new Subscription
            for(Host h : _activeHosts) {
                if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                    double proportionKnown = -1;

                    if(_subscriptionBased) {
                        int numKnownSubs = 0;
                        int numTotalSubs = 0;

                        for(Subscription hostsub : h.getCurrentSubscriptions()) {
                            numTotalSubs++;
                            if(sub.hasSeenSubscription(hostsub)) {
                                numKnownSubs++;
                            }
                        }

                        proportionKnown = (double)numKnownSubs/numTotalSubs;
                    } else {
                        int numKnownSubVMs = 0;
                        int numTotalVMs = h.getCurrentVMs().size();
                        // Calculate the maximum number of unknown VMs that we may encounter, so that we can break
                        // the loop if the proportion of seen VMs is clearly worse than the previously best proportion.
                        int maxUnknownSubVMs = numTotalVMs - (int)(bestProportionKnown * numTotalVMs);

                        for (VM hostvm : h.getCurrentVMs()) {
                            Subscription hostsub = hostvm.getSubscription();
                            if (sub.hasSeenSubscription(hostsub)) {
                                numKnownSubVMs++;
                            } else {
                                maxUnknownSubVMs--;
                                if(maxUnknownSubVMs < 0) {
                                    break;
                                }
                            }
                        }

                        if(maxUnknownSubVMs >= 0) {
                            proportionKnown = (double) numKnownSubVMs / numTotalVMs;
                        } else {
                            proportionKnown = -1;
                        }
                    }

                    if(proportionKnown > bestProportionKnown) {
                        eligibleHosts = new ArrayList<Host>();
                        eligibleHosts.add(h);
                        bestProportionKnown = proportionKnown;
                    } else if(proportionKnown == bestProportionKnown) {
                        eligibleHosts.add(h);
                    } // else ignore the host
                }
            }

            if(_lowestAvgSeenForNewSubs && bestProportionKnown == 0) {
                ArrayList<Host> freeHosts = eligibleHosts;
                eligibleHosts = new ArrayList<Host>();

                double lowestAvgSeenSubs = Double.MAX_VALUE;
                for(Host h : freeHosts) {
                    int seenSubs = 0;
                    int num = 0;

                    if(_subscriptionBased) {
                        for(Subscription s : h.getCurrentSubscriptions()) {
                            seenSubs += s.getSeenSubscriptions().size();
                            num++;
                        }
                    } else {
                        for(VM v : h.getCurrentVMs()) {
                            seenSubs += v.getSubscription().getSeenSubscriptions().size();
                            num++;
                        }
                    }

                    double avgSeen = (double)seenSubs / num;

                    if(avgSeen < lowestAvgSeenSubs) {
                        lowestAvgSeenSubs = avgSeen;
                        eligibleHosts = new ArrayList<Host>();
                        eligibleHosts.add(h);
                    } else if(avgSeen == lowestAvgSeenSubs) {
                        eligibleHosts.add(h);
                    } // else ignore h
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
