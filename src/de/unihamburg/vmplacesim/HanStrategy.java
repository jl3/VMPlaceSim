// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.ArrayList;
import java.util.Random;

/**
 * Implements the PSSF placement strategy proposed by Han et al. with the assumption that empty servers in an active
 * group are turned off. This is the implementation used for the evaluation in the paper accompanying this
 * framework.
 *
 * @author Jens Lindemann
 */
public class HanStrategy extends PlacementStrategy {
    private int _nstar;
    private int _nG;

    private boolean[] _groupActive;
    private int[] _groupHostsNonEmpty;

    public HanStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int nstar, int maliciousSets) {
        // Call super constructor. activeHosts is set to 0, as the super constructor would activate *random* Hosts
        // instead of a specific group.
        super(numberOfHosts, 0, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, false, true);

        this._nstar = nstar;
        this._nG = activeHosts;
        this._groupActive = new boolean[numberOfHosts / _nG];
        this._groupHostsNonEmpty = new int[numberOfHosts / _nG];
        activateGroup(0);
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        Subscription sub = vm.getSubscription();

        ArrayList<Host> psslist = new ArrayList<Host>();
        ArrayList<Host> npsslist = new ArrayList<Host>();
        for(int g = 0; g < _hosts.length / _nG; g++) {
            if(!_groupActive[g]) {
                continue;
            }

            for(int hostno = 0; hostno < _nG; hostno++) {
                Host h = _hosts[(g*_nG)+hostno];
                if ((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                    if (h.hasHostedSubscription(sub)) {
                        int numSubVMs = 0;
                        for (VM hostvm : h.getCurrentVMs()) {
                            Subscription hostvmsub = hostvm.getSubscription();
                            if (sub.equals(hostvmsub)) {
                                numSubVMs++;
                            }
                        }

                        if (numSubVMs < _nstar) {
                            psslist.add(h);
                        }
                    } else {
                        npsslist.add(h);
                    }
                }
            }
        }

        Host chosenHost = null;
        if(!psslist.isEmpty()) {
            chosenHost =  pickRandomHost(psslist);
        } else if(!npsslist.isEmpty()) {
            int minHostNumber = Integer.MAX_VALUE;
            for(Host h : npsslist) {
                if(h.getHostNumber() < minHostNumber) {
                    minHostNumber = h.getHostNumber();
                }
            }

            int groupNumber = minHostNumber / _nG;
            int maxFreeCores = Integer.MIN_VALUE;
            ArrayList<Host> mostFreeCoresHosts = new ArrayList<Host>();
            for(int i = groupNumber * _nG; i < (groupNumber+1) * _nG; i++) {
                Host h = _hosts[i];
                if(h.freeCores() > maxFreeCores) {
                    mostFreeCoresHosts = new ArrayList<Host>();
                    maxFreeCores = h.freeCores();
                    mostFreeCoresHosts.add(h);
                } else if(h.freeCores() == maxFreeCores) {
                    mostFreeCoresHosts.add(h);
                } // else ignore the Host.
            }

            chosenHost = pickRandomHost(mostFreeCoresHosts);
        } else { // all Hosts in active groups are full
            // Activate additional group, choose random Host.
            boolean foundInactiveGroup = false;
            for(int i = 0; i < _groupActive.length; i++) {
                if(!_groupActive[i]) {
                    Host[] grouphosts = activateGroup(i);
                    chosenHost = pickRandomHost(grouphosts);
                    foundInactiveGroup = true;
                    break;
                }
            }

            if(!foundInactiveGroup) {
                System.exit(1);
                System.err.println("All Hosts are out of capacity!");
                return null;
            }
        }

        return chosenHost;
    }

    @Override
    protected void createVM(VM vm, Host host) {
        if(host.numberOfCurrentVMs() == 0) {
            int groupNumber = host.getHostNumber() / _nG;
            _groupHostsNonEmpty[groupNumber]++;
        }
        super.createVM(vm, host);
    }

    @Override
    protected void deleteVM(VM vm) {
        Host h = vm.getCurrentHost();
        boolean hostEmpty = deleteVM(vm, true);
        if(hostEmpty) {
            // Check if all Hosts in group are empty.
            int groupNumber = h.getHostNumber() / _nG;
            _groupHostsNonEmpty[groupNumber]--;
            /*boolean allVMsEmpty = true;
            for(int i = groupNumber * _nG; i < (groupNumber+1) * _nG; i++) {
                if(_hosts[i].numberOfCurrentVMs() > 0) {
                    allVMsEmpty = false;
                    break;
                }
            }*/

            //if(allVMsEmpty) {
            if(_groupHostsNonEmpty[groupNumber] == 0) {
                for(int i = groupNumber * _nG; i < (groupNumber+1) * _nG; i++) {
                    this.deactivateHost(_hosts[i], _time);
                }

                _groupActive[groupNumber] = false;
            }
        }
    }

    private Host[] activateGroup(int groupNumber) {
        Host[] grouphosts = new Host[_nG];
        for(int j = 0; j < _nG; j++) {
            grouphosts[j] = _hosts[j+(groupNumber*_nG)];
            //this.activateHost(_hosts[j+(groupNumber*_nG)], _time);
        }
        _groupActive[groupNumber] = true;
        return grouphosts;
    }
}
