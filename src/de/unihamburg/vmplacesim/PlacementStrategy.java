// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.*;

/**
 * Abstract class representing a VM placement strategy. This class can be extended to implment a concrete
 * placement strategy for use with the simulation framework.
 *
 * @author Jens Lindemann
 */
public abstract class PlacementStrategy {
    protected ArrayList<Host> _activeHosts;
    protected ArrayList<Host> _inactiveHosts;

    protected Host[] _hosts;

    protected int _time;

    protected Random _rnd;

    private int _startTime;
    private int _statInterval;
    private int _nextStat;
    private String _cuStatStr;
    private String _intcuStatStr;
    private String[] _userCLRStr;
    private String[] _vmCLRStr;
    private String[] _newVMCLRStr;
    private String[] _unsafeSubVMCLRStr;
    private String[] _unsafeSubNewVMCLRStr;
    protected String[] _coverageStr;
    private String _avgVMStr;
    private String _maxVMStr;
    private String _minVMStr;
    private String _avgHostsStr;
    private String _maxHostsStr;
    private String _minHostsStr;
    private String _vmCreationsStr;
    private String _vmDeletionsStr;
    private String _hostsBootedStr;
    private String _hostsShutDownStr;
    private HashSet<Subscription> _processedSubscriptions;

    private int _maxHostsActive;
    private int _maxHostsActiveInterval;
    private int _minHostsActiveInterval;
    private int _maxVMsActive;
    private BigInteger _vmTicks;
    private BigInteger _hostTicks;
    private BigInteger _intervalHostTicks;
    private int _lastHostEvent;
    private int _intervalLastHostEvent;
    private int _intervalHostsBooted;
    private int _intervalHostsShutDown;
    private int _hostsBooted;
    private int _hostsShutDown;
    private int _maliciousSets;
    private int _totalSubKnownEntries;
    private double _avgSubsKnownPerSub;
    private int _totalSubsSeenByHosts;
    private double _avgHostsSeenPerSub;
    private double _avgSubsSeenPerHost;

    private int _vmTargetsHit;
    private int _vmsWithTargets;
    private int _subVMTargetsHit;
    private int _totalSubTargetVMs;

    private boolean _generateSubsSeenStats;
    private boolean _generateHostsSeenStats;

    /**
     * Constructor for a placement strategy.
     *
     * @param numberOfHosts number of hosts in the simulation
     * @param activeHosts number of hosts intitially active
     * @param coresPerHost CPU cores per host
     * @param memoryPerHost memory per host
     * @param random PRNG
     * @param startTime start time of simulation
     * @param statInterval interval in which sub-period statistics are generated
     * @param statMinTime first time for which to generate statistics
     * @param maliciousSets number of different sets of malicious users in simulation
     * @param generateSubsSeenStats true if statistics about the number of other subscriptions seen by subscriptions
     *                              shall be generated, false otherwise
     * @param generateHostsSeenStats true if statistics about the number of hosts seen by subscriptons shall be
     *                               generated, false otherwise
     */
    public PlacementStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets, boolean generateSubsSeenStats, boolean generateHostsSeenStats) {
        _activeHosts = new ArrayList<Host>();
        _inactiveHosts = new ArrayList<Host>();
        _startTime = startTime;
        _nextStat = statMinTime + statInterval;
        _processedSubscriptions = new HashSet<Subscription>();
        _statInterval = statInterval;
        _maxHostsActive = 0;
        _maxHostsActiveInterval = 0;
        _minHostsActiveInterval = 0;
        _maxVMsActive = 0;
        _vmTicks = BigInteger.ZERO;
        _hostTicks = BigInteger.ZERO;
        _lastHostEvent = _startTime;
        _intervalHostTicks = BigInteger.ZERO;
        _intervalLastHostEvent = _startTime;
        _intervalHostsBooted = 0;
        _intervalHostsShutDown = 0;
        _hostsBooted = 0;
        _hostsShutDown = 0;
        _maliciousSets = maliciousSets;
        _totalSubKnownEntries = -1;
        _avgSubsKnownPerSub = -1;
        _generateSubsSeenStats = generateSubsSeenStats;
        _totalSubsSeenByHosts = -1;
        _avgHostsSeenPerSub = -1;
        _avgSubsSeenPerHost = -1;
        _generateHostsSeenStats = generateHostsSeenStats;

        _cuStatStr = new String();
        _intcuStatStr = new String();
        _userCLRStr = new String[maliciousSets];
        _vmCLRStr = new String[maliciousSets];
        _newVMCLRStr = new String[maliciousSets];
        _unsafeSubVMCLRStr = new String[maliciousSets];
        _unsafeSubNewVMCLRStr = new String[maliciousSets];
        _coverageStr = new String[maliciousSets];
        _avgVMStr = new String();
        _maxVMStr = new String();
        _minVMStr = new String();
        _avgHostsStr = new String();
        _maxHostsStr = new String();
        _minHostsStr = new String();
        _vmCreationsStr = new String();
        _vmDeletionsStr = new String();
        _hostsBootedStr = new String();
        _hostsShutDownStr = new String();

        _vmTargetsHit = 0;
        _vmsWithTargets = 0;
        _subVMTargetsHit = 0;
        _totalSubTargetVMs = 0;

        for(int ms = 0; ms < maliciousSets; ms++) {
            _userCLRStr[ms] = new String();
            _vmCLRStr[ms] = new String();
            _newVMCLRStr[ms] = new String();
            _unsafeSubVMCLRStr[ms] = new String();
            _unsafeSubNewVMCLRStr[ms] = new String();
            _coverageStr[ms] = new String();
        }

        _hosts = new Host[numberOfHosts];
        for(int i = 0; i < numberOfHosts; i++) {
            _hosts[i] = new Host(coresPerHost, memoryPerHost, i, maliciousSets);
            _inactiveHosts.add(_hosts[i]);
        }
        _rnd = random;

        // Make some (randomly chosen) hosts active
        for(int i = 0; i < activeHosts; i++) {
            activateHost(pickRandomHost(_inactiveHosts), startTime);
        }
    }

    /**
     * Performs the placement simulation.
     *
     * @param vmCreations VMs ordered in their order of creation
     * @param vmDeletions VMs ordered in their order of deletion
     */
    public void simulatePlacements(VM[] vmCreations, VM[] vmDeletions) {
        _time = _startTime;

        int c = 0;
        int d = 0;

        int noVMsRunning = 0;
        int intervalMaxVMs = 0;
        int intervalMinVMs = 0;
        BigInteger intervalVMTicks = BigInteger.ZERO;
        int intervalVMCreations = 0;
        int intervalVMDeletions = 0;
        int intervalStartC = 0;
        int intervalEndC = 0;

        VM createVM = vmCreations[c];
        VM deleteVM = vmDeletions[d];
        do {
            // If the times are equal, create before deleting -- There are VMs that are instantly deleted in the dataset...
            // Also, this avoids underestimating the resource requirements
            if(createVM == null || deleteVM.getTimeDeleted() < createVM.getTimeCreated()) {
                int newTime = deleteVM.getTimeDeleted();

                // Trigger interval statistics update if it is time
                int intervalTime = _time;
                while(newTime > _nextStat) {
                    int intervalTimediff = _nextStat - intervalTime;
                    intervalVMTicks = intervalVMTicks.add(BigInteger.valueOf(intervalTimediff).multiply(BigInteger.valueOf(noVMsRunning)));

                    intervalTime = _nextStat;
                    intervalStartC = intervalEndC;
                    intervalEndC = c-1;
                    updateStats(vmCreations, c-1, intervalVMTicks, intervalMaxVMs, intervalMinVMs, intervalVMCreations, intervalVMDeletions, intervalStartC, intervalEndC);
                    intervalVMTicks = BigInteger.ZERO;
                    intervalMaxVMs = noVMsRunning;
                    intervalMinVMs = noVMsRunning;
                    intervalVMCreations = 0;
                    intervalVMDeletions = 0;
                }

                // Update the counter for total VM activity time
                int timediff = newTime - _time;
                _vmTicks = _vmTicks.add(BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(noVMsRunning)));

                int intervalTimediff = newTime - intervalTime;
                intervalVMTicks = intervalVMTicks.add(BigInteger.valueOf(intervalTimediff).multiply(BigInteger.valueOf(noVMsRunning)));

                // Update statistics regarding the number of running VMs
                noVMsRunning--;
                if(noVMsRunning < intervalMinVMs) {
                    intervalMinVMs = noVMsRunning;
                }

                intervalVMDeletions++;

                _time = newTime;

                deleteVM(deleteVM);

                // Retrieve the next VM to be deleted
                d++;
                if(d < vmDeletions.length) {
                    deleteVM = vmDeletions[d];

                    if(d % 10000 == 0) {
                        System.err.println("Processing deletion " + d + " of " + vmDeletions.length);
                    }
                } else {
                    deleteVM = null;
                }
            } else { // Process a VM creation
                int newTime = createVM.getTimeCreated();

                // Trigger interval statistics update if it is time
                int intervalTime = _time;
                while(newTime > _nextStat) {
                    int intervalTimediff = _nextStat - intervalTime;
                    intervalVMTicks = intervalVMTicks.add(BigInteger.valueOf(intervalTimediff).multiply(BigInteger.valueOf(noVMsRunning)));

                    intervalTime = _nextStat;
                    intervalStartC = intervalEndC;
                    intervalEndC = c-1;
                    updateStats(vmCreations, c-1, intervalVMTicks, intervalMaxVMs, intervalMinVMs, intervalVMCreations, intervalVMDeletions, intervalStartC, intervalEndC);
                    intervalVMTicks = BigInteger.ZERO;
                    intervalMaxVMs = noVMsRunning;
                    intervalMinVMs = noVMsRunning;
                    intervalVMCreations = 0;
                    intervalVMDeletions = 0;
                }

                // Update the counter for total VM activity time
                int timediff = newTime - _time;
                _vmTicks = _vmTicks.add(BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(noVMsRunning)));

                int intervalTimediff = newTime - intervalTime;
                intervalVMTicks = intervalVMTicks.add(BigInteger.valueOf(intervalTimediff).multiply(BigInteger.valueOf(noVMsRunning)));

                intervalVMCreations++;

                // Update statistics regarding the number of running VMs
                noVMsRunning++;

                if(noVMsRunning > intervalMaxVMs) {
                    intervalMaxVMs = noVMsRunning;
                }

                if(noVMsRunning > _maxVMsActive) {
                    _maxVMsActive = noVMsRunning;
                }

                _time = newTime;

                createVM(createVM);
                _processedSubscriptions.add(createVM.getSubscription());

                // Check if target hit
                if(createVM.hasTarget()) {
                    Host host = createVM.getHost();
                    VM targetVM = createVM.getTargetVM();
                    Subscription targetSub = createVM.getTargetSubscription();
                    _vmsWithTargets++;

                    if(host.getCurrentVMs().contains(targetVM)) {
                        createVM.setTargetHit();
                        _vmTargetsHit++;
                    }

                    // We do not need to check if host hosts targetSub, as VM.setTargetHit also reports the hit
                    // to the Subscription
                }

                // Retrieve the next VM to be created
                c++;
                if(c < vmCreations.length) {
                    createVM = vmCreations[c];

                    if(c % 10000 == 0) {
                        System.err.println("Processing creation " + c + " of " + vmCreations.length);
                    }
                } else {
                    createVM = null;
                }
            }
        } while((createVM != null) || (deleteVM != null)); // End if there are no creations or deletions left to process

        // Update stats one last time
        int intervalTimediff = _nextStat - _time;
        intervalVMTicks = intervalVMTicks.add(BigInteger.valueOf(intervalTimediff).multiply(BigInteger.valueOf(noVMsRunning)));
        intervalStartC = intervalEndC;
        intervalEndC = c-1;
        updateStats(vmCreations, c-1, intervalVMTicks, intervalMaxVMs, intervalMinVMs, intervalVMCreations, intervalVMDeletions, intervalStartC, intervalEndC);
    }

    /**
     * Deleted a VM, shutting down the host if it is empty after the deletion.
     *
     * @param vm VM to delete
     */
    protected void deleteVM(VM vm) {
        deleteVM(vm, true);
    }

    /**
     * Deletes a VM.
     *
     * @param vm VM to delete
     * @param shutdownHostIfEmpty If true, the host will be shut down if it is empty after the deletion. If false,
     *                            it will remain active.
     * @return true if the Host is now empty, false if there are still VMs remaining on the Host
     */
    protected boolean deleteVM(VM vm, boolean shutdownHostIfEmpty) {
        Host h = vm.getCurrentHost();
        h.deleteVM(vm);

        if(shutdownHostIfEmpty && h.numberOfCurrentVMs() == 0) {
            this.deactivateHost(h, _time);
        }

        vm.getSubscription().deleteVM(vm);

        return h.numberOfCurrentVMs() == 0;
    }

    /**
     * Creates a VM.
     *
     * @param vm VM to create
     */
    protected void createVM(VM vm) {
        Host host = pickHost(vm);
        if(!host.isActive()) {
            activateHost(host, _time);
        }
        createVM(vm, host);
    }

    /**
     * Creates a VM.
     *
     * @param vm VM to create
     * @param host Host on which to create the VM
     */
    protected void createVM(VM vm, Host host) {
        if(!host.isActive()) {
            activateHost(host, _time);
        }
        host.createVM(vm);
        vm.getSubscription().createVM(vm);
        //vm.getDeployment().createVM(vm);
    }

    /**
     * Activates a random Host.
     *
     * @return the Host that was activated
     */
    protected Host activateHost() {
        if(_inactiveHosts.size() == 0) {
            return null;
        } else {
            Host h = _inactiveHosts.get(_rnd.nextInt(_inactiveHosts.size()));
            activateHost(h, _time);
            return h;
        }
    }

    /**
     * Activates a specific Host at a specific time.
     *
     * Note that this does not schedule an event for the future. The method should only be called at the appropriate
     * time in the simulation. The time is needed in this method for updating the statistics.
     *
     * @param host the Host to activate
     * @param time the time at which the Host is deactivated
     */
    protected void activateHost(Host host, int time) {
        // Update statistics referring to hosts, including the cumulative time of hosts active
        int noOfActiveHosts = numberOfRunningHosts();
        int timediff = time - _lastHostEvent;
        _hostTicks = _hostTicks.add(BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(noOfActiveHosts)));
        int intervaltimediff = time - _intervalLastHostEvent;
        _intervalHostTicks = _intervalHostTicks.add(BigInteger.valueOf(intervaltimediff).multiply(BigInteger.valueOf(noOfActiveHosts)));
        _intervalHostsBooted++;
        _hostsBooted++;

        // Activate the host
        host.boot(time);
        _inactiveHosts.remove(host);
        _activeHosts.add(host);

        // Update maximum host statistics, if the current number of active hosts is higher than the old maximum.
        noOfActiveHosts++;
        if(noOfActiveHosts > _maxHostsActive) {
            _maxHostsActive = noOfActiveHosts;
        }

        if(noOfActiveHosts > _maxHostsActiveInterval) {
            _maxHostsActiveInterval = noOfActiveHosts;
        }

        _lastHostEvent = time;
        _intervalLastHostEvent = time;
    }

    /**
     * Deactivates a specific Host at a specific time.
     *
     * Note that this does not schedule an event for the future. The method should only be called at the appropriate
     * time in the simulation. The time is needed in this method for updating the statistics.
     *
     * @param host the Host to deactivate
     * @param time the time at which the Host is deactivated
     */
    protected void deactivateHost(Host host, int time) {
        // Update statistics referring to hosts, including the cumulative time of hosts active
        int noOfActiveHosts = numberOfRunningHosts();
        int timediff = time - _lastHostEvent;
        _hostTicks = _hostTicks.add(BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(noOfActiveHosts)));
        int intervaltimediff = time - _intervalLastHostEvent;
        _intervalHostTicks = _intervalHostTicks.add(BigInteger.valueOf(intervaltimediff).multiply(BigInteger.valueOf(noOfActiveHosts)));
        _intervalHostsShutDown++;
        _hostsShutDown++;

        // Deactivate the host
        host.shutdown(time);
        _activeHosts.remove(host);
        _inactiveHosts.add(host);

        // Update minimum host statistics, if the current number of active hosts is lower than the old interval minimum.
        noOfActiveHosts--;
        if(noOfActiveHosts < _minHostsActiveInterval) {
            _minHostsActiveInterval = noOfActiveHosts;
        }

        _lastHostEvent = time;
        _intervalLastHostEvent = time;
    }

    /**
     * Calculate user-based CLR (CLR as defined by Agarwal et al.)
     *
     * @param subs The subscriptions used in the simulation
     * @param malSet the index of the set of malicious users for which to calculate the user-based CLR
     * @return user-based CLR
     */
    public double calculateUserBasedCLR(Subscription[] subs, int malSet) {
        int subsBenign = 0;
        int subsExposedToMaliciousSub = 0;

        for(Subscription sub : subs) {
            if(!sub.isMalicious(malSet)) {
                subsBenign++;
                if(sub.wasExposedToMaliciousSub(malSet)) {
                    subsExposedToMaliciousSub++;
                }
            }
        }

        return ((double)subsBenign - subsExposedToMaliciousSub) / subsBenign;
    }

    /**
     * Calculates the VM-based CLR (introduced in the paper)
     *
     * @param vms The VMs used in the simulation so far
     * @param malSet the index of the set of malicious users for which to calculate the VM-based CLR
     * @return VM-based CLR
     */
    public static double calculateVmBasedCLR(VM[] vms, int malSet) {
        int vmsBenign = 0;
        int vmsExposedToMaliciousVM = 0;

        for(VM vm : vms) {
            if(!vm.isMalicious(malSet)) {
                vmsBenign++;
                if(vm.wasColocatedWithMaliciousVM(malSet)) {
                    vmsExposedToMaliciousVM++;
                }
            }
        }

        return ((double)vmsBenign - vmsExposedToMaliciousVM) / vmsBenign;
    }

    /**
     * Calculates the VM-based CLR retricted to unsafe subscriptions
     *
     * @param vms the VMs used in the simulation so far
     * @param malSet the index of the set of malicious users for which to calculate the VM-based CLR
     * @return unsafe user VM-based CLR
     */
    public static double calculateUnsafeSubVmBasedCLR(VM[] vms, int malSet) {
        int vmsBenign = 0;
        int vmsExposedToMaliciousVM = 0;

        for(VM vm : vms) {
            if(!vm.isMalicious(malSet)) {
                Subscription sub = vm.getSubscription();
                if(sub.wasExposedToMaliciousSub(malSet)) {
                    vmsBenign++;
                    if(vm.wasColocatedWithMaliciousVM(malSet)) {
                        vmsExposedToMaliciousVM++;
                    }
                }
            }
        }

        return ((double)vmsBenign - vmsExposedToMaliciousVM) / vmsBenign;
    }

    /**
     * Calculates the safe-VM time proportion (cf. paper)
     *
     * @param vmCreations VM creation events
     * @param malSet the index of the set of malicious users for which to calculate the statistic
     * @return safe-VM time proportion
     */
    public static BigDecimal[] calculateSafeVMTimeProportion(VM[] vmCreations, int malSet) {
        BigInteger totalVMTime = BigInteger.ZERO;
        BigInteger unsafeVMTime = BigInteger.ZERO;

        BigInteger totalUnsafeSubVMTime = BigInteger.ZERO;
        BigInteger unsafeSubUnsafeVMTime = BigInteger.ZERO;

        for(VM vm : vmCreations) {
            if(vm.isMalicious(malSet)) {
                continue;
            }

            int vmcreation = vm.getTimeCreated();
            int vmdeletion = vm.getTimeDeleted();
            int timeActive = vmdeletion - vmcreation;
            totalVMTime = totalVMTime.add(BigInteger.valueOf(timeActive));

            if(vm.getSubscription().wasExposedToMaliciousSub(malSet)) {
                totalUnsafeSubVMTime = totalUnsafeSubVMTime.add(BigInteger.valueOf(timeActive));
            }

            Host h = vm.getHost();
            for(int i = 0; i < h.numberOfMaliciousPeriods(malSet); i++) {
                int[] mp = h.getMaliciousPeriod(i, malSet);

                if ((mp[0] < vmcreation && mp[1] < vmdeletion) ||
                        (mp[0] > vmcreation && mp[1] > vmdeletion)) {
                    // Malicious period outside VM lifetime -> ignore
                    continue;
                }

                int mpstart = mp[0];
                if (mp[0] < vmcreation) {
                    mpstart = vmcreation;
                }

                int mpend = mp[1];
                if (mp[1] > vmdeletion) {
                    mpend = vmdeletion;
                }

                int mplength = mpend - mpstart;
                unsafeVMTime = unsafeVMTime.add(BigInteger.valueOf(mplength));

                if (vm.getSubscription().wasExposedToMaliciousSub(malSet)) {
                    unsafeSubUnsafeVMTime = unsafeSubUnsafeVMTime.add(BigInteger.valueOf(mplength));
                }
            }
        }

        BigDecimal safeVMTimeProportion;
        if(!totalVMTime.equals(BigInteger.ZERO)) {
            BigInteger safeVMTime = totalVMTime.subtract(unsafeVMTime);
            safeVMTimeProportion = new BigDecimal(safeVMTime).divide(new BigDecimal(totalVMTime), 10, RoundingMode.HALF_UP);
        } else {
            safeVMTimeProportion = BigDecimal.ONE;
        }

        BigDecimal unsafeSubSafeVMTimeProportion;
        if(!totalUnsafeSubVMTime.equals(BigInteger.ZERO)) {
            BigInteger unsafeSubSafeVMTime = totalUnsafeSubVMTime.subtract(unsafeSubUnsafeVMTime);
            unsafeSubSafeVMTimeProportion = new BigDecimal(unsafeSubSafeVMTime).divide(new BigDecimal(totalUnsafeSubVMTime), 10, RoundingMode.HALF_UP);
        } else {
            unsafeSubSafeVMTimeProportion = BigDecimal.ONE;
        }

        BigDecimal[] ret = new BigDecimal[2];
        ret[0] = safeVMTimeProportion;
        ret[1] = unsafeSubSafeVMTimeProportion;

        return ret;
    }

    /**
     * Calculates the safe-subscription time proportion (cf. paper)
     *
     * @param subscriptions the subscriptions used in simulation
     * @param malSet the index of the set of malicious users for which to calculate the statistic
     * @return safe-subscription time proportion
     */
    public static BigDecimal calculateSafeSubscriptionTimeProportion(Subscription[] subscriptions, int malSet) {
        BigInteger totalActiveTime = BigInteger.ZERO;
        BigInteger totalUnsafeTime = BigInteger.ZERO;

        for(Subscription s : subscriptions) {
            if(s.isMalicious(malSet)) {
                continue;
            }

            ArrayList<Integer> malStart = new ArrayList<Integer>();
            ArrayList<Integer> malEnd = new ArrayList<Integer>();

            VM[] vms = s.getTotalVMs().toArray(new VM[0]);
            for(VM vm : vms) {
                Host h = vm.getHost();
                int vmcreation = vm.getTimeCreated();
                int vmdeletion = vm.getTimeDeleted();
                for(int i = 0; i < h.numberOfMaliciousPeriods(malSet); i++) {
                    int[] mp = h.getMaliciousPeriod(i, malSet);

                    if ((mp[0] < vmcreation && mp[1] < vmdeletion) ||
                            (mp[0] > vmcreation && mp[1] > vmdeletion)) {
                        // Malicious period outside VM lifetime -> ignore
                        continue;
                    }

                    int mpstart = mp[0];
                    if (mp[0] < vmcreation) {
                        mpstart = vmcreation;
                    }

                    int mpend = mp[1];
                    if (mp[1] > vmdeletion) {
                        mpend = vmdeletion;
                    }

                    for(int j = 0; j < malStart.size(); j++) {
                        if(malStart.get(j) > mpend) {
                            // Add it at j.
                            malStart.add(j, mpstart);
                            malEnd.add(j, mpend);

                            break;
                        } else if(malEnd.get(j) < mpstart) {
                            continue;
                        } else if((malStart.get(j) <= mpstart) && (malEnd.get(j) >= mpend)) {
                            break; // Can be ignored, period already covered.
                        }

                        // If none of these are the case, there is an overlap. In this case, we need two sequential ifs:
                        if(malStart.get(j) > mpstart) {
                            malStart.set(j, mpstart);
                        }

                        if(malEnd.get(j) < mpend) {
                            malEnd.set(j, mpend);
                        }

                        // check for overlap with next period(s)
                        while((j+1 < malStart.size()) && (mpend <= malStart.get(j+1))) {
                            malStart.remove(j+1);

                            if(mpend > malEnd.get(j+1)) {
                                malEnd.remove(j+1);
                            } else {
                                malEnd.remove(j);
                            }
                        }

                        break;
                    }

                    // if size=0, just add the period
                    if(malStart.size() == 0) {
                        malStart.add(mpstart);
                        malEnd.add(mpend);
                    }
                }
            }

            // Active time: When did the Subscription have active VMs?
            ArrayList<Integer> actStart = new ArrayList<Integer>();
            ArrayList<Integer> actEnd = new ArrayList<Integer>();
            for(VM vm : vms) {
                int vmstart = vm.getTimeCreated();
                int vmend = vm.getTimeDeleted();

                for(int i = 0; i < actStart.size(); i++) {
                    if(actStart.get(i) > vmend) {
                        // Add it at i.
                        actStart.add(i, vmstart);
                        actEnd.add(i, vmend);

                        break;
                    } else if(actEnd.get(i) < vmstart) {
                        continue;
                    } else if((actStart.get(i) <= vmstart) && (actEnd.get(i) >= vmend)) {
                        break; // Can be ignored, period already covered.
                    }

                    // If none of these are the case, there is an overlap. In this case, we need two sequential ifs:
                    if(actStart.get(i) > vmstart) {
                        actStart.set(i, vmstart);
                    }

                    if(actEnd.get(i) < vmend) {
                        actEnd.set(i, vmend);
                    }

                    // check for overlap with next period(s)
                    while((i+1 < actStart.size()) && (vmend <= actStart.get(i+1))) {
                        actStart.remove(i+1);

                        if(vmend > actEnd.get(i+1)) {
                            actEnd.remove(i+1);
                        } else {
                            actEnd.remove(i);
                        }
                    }

                    break;
                }

                if(actStart.size() == 0) {
                    actStart.add(vmstart);
                    actEnd.add(vmend);
                }
            }

            int subActTime = 0;
            for(int i = 0; i < actStart.size(); i++) {
                int t = actEnd.get(i) - actStart.get(i);
                subActTime += t;
            }
            totalActiveTime = totalActiveTime.add(BigInteger.valueOf(subActTime));


            int subMalTime = 0;
            for(int i = 0; i < malStart.size(); i++) {
                int t = malEnd.get(i) - malStart.get(i);
                subMalTime += t;
            }
            totalUnsafeTime = totalUnsafeTime.add(BigInteger.valueOf(subMalTime));
        }

        // return safe time / total time
        BigDecimal safeSubTimeProportion;
        if(!totalActiveTime.equals(BigInteger.ZERO)) {
            BigInteger totalSafeTime = totalActiveTime.subtract(totalUnsafeTime);
            safeSubTimeProportion = new BigDecimal(totalSafeTime).divide(new BigDecimal(totalActiveTime), 10, RoundingMode.HALF_UP);
        } else {
            safeSubTimeProportion = BigDecimal.ONE;
        }
        return safeSubTimeProportion;
    }

    public BigDecimal calculateCoreUtilisation() {
        return calculateCoreUtilisation(_time);
    }

    public BigDecimal calculateCoreUtilisation(int time) {
        BigInteger busyCoreTicks = BigInteger.ZERO;
        BigInteger totalCoreTicks = BigInteger.ZERO;

        for(Host h : _hosts) {
            //busyCoreTicks += h.getBusyCoreTicks(_time);
            busyCoreTicks = busyCoreTicks.add(h.getBusyCoreTicks(time));
            BigInteger hostTotalCoreTicks = h.getTotalCoreTicks(time);
            //totalCoreTicks += hostTotalCoreTicks;
            totalCoreTicks = totalCoreTicks.add(hostTotalCoreTicks);
        }

        //double cu = (double)busyCoreTicks / totalCoreTicks;
        BigDecimal cu;
        if(!totalCoreTicks.equals(BigInteger.ZERO)) {
            cu = new BigDecimal(busyCoreTicks).divide(new BigDecimal(totalCoreTicks), 10, RoundingMode.HALF_UP);
        } else {
            cu = BigDecimal.ONE;
        }
        return cu;
    }

    public BigDecimal calculateIntervalCoreUtilisation(int time, int lastInterval) {
        BigInteger busyCoreTicks = BigInteger.ZERO;
        BigInteger totalCoreTicks = BigInteger.ZERO;

        for(Host h : _hosts) {
            //busyCoreTicks += h.getBusyCoreTicks(_time);
            busyCoreTicks = busyCoreTicks.add(h.getAndResetIntervalBusyCoreTicks(time));
            BigInteger hostTotalCoreTicks = h.getAndResetIntervalTotalCoreTicks(time, lastInterval);
            totalCoreTicks = totalCoreTicks.add(hostTotalCoreTicks);
        }

        //double cu = (double)busyCoreTicks / totalCoreTicks;
        BigDecimal cu;
        if(!totalCoreTicks.equals(BigInteger.ZERO)) {
            cu = new BigDecimal(busyCoreTicks).divide(new BigDecimal(totalCoreTicks), 10, RoundingMode.HALF_UP);
        } else {
            cu = BigDecimal.ONE;
        }
        return cu;
    }

    /**
     * Calculates the coverage (as defined by Xiao et al.).
     *
     * @param hosts The hosts used in the simulation
     * @param malSet the index of the set of malicious users for which to calculate the VM-based CLR
     * @return coverage
     */
    public static double calculateTotalCoverage(Host[] hosts, int malSet) {
        int numberOfHostsAtDanger = 0;
        int numberOfActiveHosts = 0;
        for(Host h : hosts) {
            if(h.numberOfBoots() > 0) {
                numberOfActiveHosts++;
                if(h.numberOfMaliciousPeriods(malSet) > 0) {
                    numberOfHostsAtDanger++;
                }
            }
        }

        double totalCoverage = (double)numberOfHostsAtDanger / numberOfActiveHosts;
        return totalCoverage;
    }

    /**
     * Picks a random inactive/empty Host to host a VM.
     *
     * This *may* return null if there is no Host with sufficient capacity.
     *
     * @param vm VM to host
     * @return The Host selected to host the VM
     */
    protected Host pickEmptyHost(VM vm) {
        ArrayList<Host> eligibleHosts = new ArrayList<Host>();
        for(Host h :_inactiveHosts) {
            if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                eligibleHosts.add(h);
            }
        }

        return pickRandomHost(eligibleHosts);
    }

    /**
     * Picks a random Host from an ArrayList.
     *
     * @param hosts the Hosts to choose from
     * @return a random Host from the ArrayList provided
     */
    protected Host pickRandomHost(ArrayList<Host> hosts) {
        return hosts.get(_rnd.nextInt(hosts.size()));
    }

    /**
     * Picks a random Host from a HashSet.
     *
     * @param hosts the Hosts to choose from
     * @return a random Host from the HashSet provided
     */
    @Deprecated
    protected Host pickRandomHost(HashSet<Host> hosts) {
        Host[] hostArray = hosts.toArray(new Host[0]);
        return pickRandomHost(hostArray);
    }

    /**
     * Picks a random Host from an array.
     *
     * @param hosts the Hosts to choose from
     * @return a random Host from the array provided
     */
    protected Host pickRandomHost(Host[] hosts) {
        if(hosts.length > 0) {
            return hosts[_rnd.nextInt(hosts.length)];
        } else {
            return null;
        }
    }

    /**
     * Deactivates random empty hosts
     *
     * @param numHosts the number of hosts to deactivate
     * @return true if an empty Host was deactivated, false if there is no empty Host.
     */
    protected boolean deactivateEmptyHosts(int numHosts) {
        LinkedList<Host> deactivate = new LinkedList<Host>();

        for(Host h : _activeHosts) {
            if(h.numberOfCurrentVMs() == 0) {
                deactivate.add(h);
                numHosts--;
                if(numHosts == 0) {
                    break;
                }
            }
        }

        for(Host h : deactivate) {
            deactivateHost(h, _time);
        }

        return numHosts == 0;
    }

    /**
     * This method is called in each interval to update the statistics.
     */
    private void updateStats(VM[] vms, int c, BigInteger intervalVMTicks, int intervalMaxVMs, int intervalMinVMs, int intervalVMCreations, int intervalVMDeletions, int intervalStartC, int intervalEndC) {
        System.out.println("Updating stats for time " + _nextStat);

        if(!_cuStatStr.isEmpty()) {
            _cuStatStr += ";";
        }

        BigDecimal cu = calculateCoreUtilisation(_nextStat);
        _cuStatStr += cu.toString();

        if(!_intcuStatStr.isEmpty()) {
            _intcuStatStr += ";";
        }

        BigDecimal intcu = calculateIntervalCoreUtilisation(_nextStat, _nextStat-_statInterval);
        _intcuStatStr += intcu.toString();

        Subscription[] processedSubsArray = _processedSubscriptions.toArray(new Subscription[0]);
        VM[] processedVMCreations = null;
        if(c > 0) {
            processedVMCreations = Arrays.copyOfRange(vms, 0, c);
        }
        VM[] newVMCreations = null;
        if(intervalStartC < intervalEndC) {
            newVMCreations = Arrays.copyOfRange(vms, intervalStartC, intervalEndC);
        }
        for(int ms = 0; ms < _maliciousSets; ms++) {
            if (!_userCLRStr[ms].isEmpty()) {
                _userCLRStr[ms] += ";";
            }

            // toArray is not terribly efficient, but this is not done very often...
            double userCLR = calculateUserBasedCLR(processedSubsArray, ms);
            _userCLRStr[ms] += userCLR;

            if(!_vmCLRStr[ms].isEmpty()) {
                _vmCLRStr[ms] += ";";
            }
            if(!_unsafeSubVMCLRStr[ms].isEmpty()) {
                _unsafeSubVMCLRStr[ms] += ";";
            }
            if(processedVMCreations != null) {
                double vmCLR = calculateVmBasedCLR(processedVMCreations, ms);
                _vmCLRStr[ms] += vmCLR;

                double unsafeSubVMCLR = calculateUnsafeSubVmBasedCLR(processedVMCreations, ms);
                _unsafeSubVMCLRStr[ms] += unsafeSubVMCLR;
            } else {
                _vmCLRStr[ms] += "1.0";
                _unsafeSubVMCLRStr[ms] += "1.0";
            }

            if(!_newVMCLRStr[ms].isEmpty()) {
                _newVMCLRStr[ms] += ";";
            }
            if(!_unsafeSubNewVMCLRStr[ms].isEmpty()) {
                _unsafeSubNewVMCLRStr[ms] += ";";
            }
            if(newVMCreations != null) {
                double newVMCLR = calculateVmBasedCLR(newVMCreations, ms);
                _newVMCLRStr[ms] += newVMCLR;

                double unsafeSubNewVMCLR = calculateUnsafeSubVmBasedCLR(newVMCreations, ms);
                _unsafeSubNewVMCLRStr[ms] += unsafeSubNewVMCLR;
            } else {
                _newVMCLRStr[ms] += "1.0";
                _unsafeSubNewVMCLRStr[ms] += "1.0";
            }

            if(!_coverageStr[ms].isEmpty()) {
                _coverageStr[ms] += ";";
            }

            updateCoverageStats(ms);
        }

        if(!_avgVMStr.isEmpty()) {
            _avgVMStr += ";";
        }

        BigDecimal intervalAvgVMs;
        if(_statInterval != 0) {
            intervalAvgVMs = new BigDecimal(intervalVMTicks).divide(new BigDecimal(_statInterval), 10, RoundingMode.HALF_UP);
        } else {
            intervalAvgVMs = BigDecimal.ZERO;
        }
        _avgVMStr += intervalAvgVMs;

        if(!_maxVMStr.isEmpty()) {
            _maxVMStr += ";";
        }

        _maxVMStr += intervalMaxVMs;

        if(!_minVMStr.isEmpty()) {
            _minVMStr += ";";
        }

        _minVMStr += intervalMinVMs;

        if(!_maxHostsStr.isEmpty()) {
            _maxHostsStr += ";";
        }

        _maxHostsStr += _maxHostsActiveInterval;
        _maxHostsActiveInterval = _activeHosts.size();

        if(!_minHostsStr.isEmpty()) {
            _minHostsStr += ";";
        }

        _minHostsStr += _minHostsActiveInterval;
        _minHostsActiveInterval = _activeHosts.size();

        int intervaltimediff = _nextStat - _intervalLastHostEvent;
        _intervalHostTicks = _intervalHostTicks.add(BigInteger.valueOf(intervaltimediff).multiply(BigInteger.valueOf(numberOfRunningHosts())));
        BigDecimal intervalAvgHosts = new BigDecimal(_intervalHostTicks).divide(new BigDecimal(_statInterval), 10, RoundingMode.HALF_UP);

        if(!_avgHostsStr.isEmpty()) {
            _avgHostsStr += ";";
        }

        _avgHostsStr += intervalAvgHosts;

        _intervalHostTicks = BigInteger.ZERO;
        _intervalLastHostEvent = _nextStat;

        if(!_vmCreationsStr.isEmpty()) {
            _vmCreationsStr += ";";
        }

        _vmCreationsStr += intervalVMCreations;

        if(!_vmDeletionsStr.isEmpty()) {
            _vmDeletionsStr += ";";
        }

        _vmDeletionsStr += intervalVMDeletions;

        if(!_hostsBootedStr.isEmpty()) {
            _hostsBootedStr += ";";
        }

        _hostsBootedStr += _intervalHostsBooted;
        _intervalHostsBooted = 0;

        if(!_hostsShutDownStr.isEmpty()) {
            _hostsShutDownStr += ";";
        }

        if(_generateSubsSeenStats) {
            _totalSubKnownEntries = 0;
            for (Subscription sub : processedSubsArray) {
                _totalSubKnownEntries += sub.numberOfSubscriptionsSeen();
            }
            _avgSubsKnownPerSub = (double) _totalSubKnownEntries / processedSubsArray.length;
        }

        if(_generateHostsSeenStats) {
            _totalSubsSeenByHosts = 0;
            for (Host h : _hosts) {
                _totalSubsSeenByHosts += h.numberOfSubscriptionsHosted();
            }
            _avgSubsSeenPerHost = (double) _totalSubsSeenByHosts / _hosts.length;
            _avgHostsSeenPerSub = (double) _totalSubsSeenByHosts / processedSubsArray.length;
        }

        _hostsShutDownStr += _intervalHostsShutDown;
        _intervalHostsShutDown = 0;

        _nextStat += _statInterval;
    }

    /**
     * Update method for the coverage statistics.
     *
     * @param malSet the set of malicious users for which the coverage statistics shall be updates
     */
    protected void updateCoverageStats(int malSet) {
        int hostsAtDanger = 0;
        for(Host h : _activeHosts) {
            if(h.hasMaliciousVM(malSet)) {
                hostsAtDanger++;
            }
        }
        double coverage = (double) hostsAtDanger / _activeHosts.size();
        _coverageStr[malSet] += coverage;
    }

    public String getCuStatString() {
        return _cuStatStr;
    }

    public String getIntCuStatString() {
        return _intcuStatStr;
    }

    public String getUserCLRString(int malSet) {
        return _userCLRStr[malSet];
    }

    public String getVmCLRString(int malSet) {
        return _vmCLRStr[malSet];
    }

    public String getUnsafeSubVMCLRString(int malSet) {
        return _unsafeSubVMCLRStr[malSet];
    }

    public String getUnsafeSubNewVMCLRString(int malSet) {
        return _unsafeSubNewVMCLRStr[malSet];
    }

    public String getCoverageString(int malSet) {
        return _coverageStr[malSet];
    }

    public String getAvgVMStr() {
        return _avgVMStr;
    }

    public String getMaxVMStr() {
        return _maxVMStr;
    }

    public String getMinVMStr() {
        return _minVMStr;
    }

    public String getMaxHostsStr() {
        return _maxHostsStr;
    }

    public String getMinHostsStr() {
        return _minHostsStr;
    }

    public String getAvgHostsStr() {
        return _avgHostsStr;
    }

    public String getVMCreationsStr() {
        return _vmCreationsStr;
    }

    public String getVMDeletionsStr() {
        return _vmDeletionsStr;
    }

    public String getHostsBootedStr() {
        return _hostsBootedStr;
    }

    public String getHostsShutDownStr() {
        return _hostsShutDownStr;
    }

    public String getNewVMCLRStr(int malSet) {
        return _newVMCLRStr[malSet];
    }

    public int getMaxHostsActive() {
        return _maxHostsActive;
    }

    public int getMaxVMsActive() {
        return _maxVMsActive;
    }

    public int getHostsBooted() {
        return _hostsBooted;
    }

    public int getHostsShutDown() {
        return _hostsShutDown;
    }

    public int getTotalSubKnownEntries() {
        return _totalSubKnownEntries;
    }

    public double getAvgSubsKnownPerSub() {
        return _avgSubsKnownPerSub;
    }

    public int getTotalSubsSeenByHosts() {
        return _totalSubsSeenByHosts;
    }

    public double getAvgSubsSeenPerHost() {
        return _avgSubsSeenPerHost;
    }

    public double getAvgHostsSeenPerSub() {
        return _avgHostsSeenPerSub;
    }

    public BigDecimal getAvgActiveVMs() {
        BigDecimal timediff = BigDecimal.valueOf(_time -_startTime);
        BigDecimal avgActiveVMs = new BigDecimal(_vmTicks).divide(timediff, 10, RoundingMode.HALF_UP);
        return avgActiveVMs;
    }

    public BigDecimal getAvgActiveHosts() {
        if(_time != _lastHostEvent) {
            int ticksTimediff = _time - _lastHostEvent;
            _hostTicks = _hostTicks.add(BigInteger.valueOf(ticksTimediff).multiply(BigInteger.valueOf(numberOfRunningHosts())));
        }
        BigDecimal timediff = BigDecimal.valueOf(_time - _startTime);
        BigDecimal avgActiveHosts = new BigDecimal(_hostTicks).divide(timediff, 10, RoundingMode.HALF_UP);
        return avgActiveHosts;
    }

    protected int numberOfRunningHosts() {
        return _activeHosts.size();
    }

    /**
     * This is an abstract method for picking a host. This must be overwritten by every implementing placement
     * strategy class. It contains the main logic of a placement strategy, i.e. how it chooses a host for a new VM.
     *
     * @param vm the VM to host
     * @return the Host selected for the VM
     */
    protected abstract Host pickHost(VM vm);
}
