// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.math.BigInteger;
import java.util.*;

/**
 * This class represents one of the hosts in a cloud environment in the siimulation. It can be started and shut down.
 * VMs can be allocated to and deallocated from it.
 *
 * @author Jens Lindemann
 */
public class Host {
	private int _cores;
	private double _memory;
	
	// VMs currently hosted
	private ArrayList<VM> _currentVMs;
	// all VMs hosted over time (ordered by time of start, can have duplicates
	// if VM booted more than once)
	private ArrayList<VM> _allVMs;

	private int[] _currentMaliciousVMs;
	// ArrayLists to keep track of periods with malicious VM(s) on host
	private ArrayList<Integer>[] _maliciousStart;
	private ArrayList<Integer>[] _maliciousEnd;

	private HashSet<Subscription> _subsHosted;
	private HashMap<Subscription, Integer> _subVMsHosted;
	
	private int _coresBusy;
	private double _memoryUsed; // TODO Could re-implement this to use int/long, but this should not cause trouble...
	
	private BigInteger _busyCoreTicks;
	private BigInteger _totalCoreTicks;
	private int _lastEvent;

	private BigInteger _intervalTotalCoreTicks;
	private int _lastIntervalForTotalCoreTicks;
	private BigInteger _intervalBusyCoreTicks;
	private int _lastIntervalEvent;
	
	private int _booted;
	private int _numberOfBoots;
	private int _hostNumber;

	private int _maliciousSets;
	
	public Host(int cores, double memory, int hostNumber, int maliciousSets) {
		this._cores = cores;
		this._memory = memory;
		this._currentMaliciousVMs = new int[maliciousSets];
		this._lastEvent = 0;
		this._totalCoreTicks = BigInteger.ZERO;
		this._busyCoreTicks = BigInteger.ZERO;
		this._intervalTotalCoreTicks = BigInteger.ZERO;
		this._intervalBusyCoreTicks = BigInteger.ZERO;
		this._lastIntervalEvent = 0;
		this._lastIntervalForTotalCoreTicks = 0;
		this._booted = Integer.MIN_VALUE; // = not active
		this._numberOfBoots = 0;

		this._currentVMs = new ArrayList<VM>();
		this._allVMs = new ArrayList<VM>();
		this._maliciousStart = new ArrayList[maliciousSets];
		this._maliciousEnd = new ArrayList[maliciousSets];

		for(int ms = 0; ms < maliciousSets; ms++) {
			_maliciousStart[ms] = new ArrayList<Integer>();
			_maliciousEnd[ms] = new ArrayList<Integer>();
		}

		this._subsHosted = new HashSet<Subscription>();
		this._subVMsHosted = new HashMap<Subscription, Integer>();
		this._hostNumber = hostNumber;

		this._maliciousSets = maliciousSets;
	}
	
	public boolean createVM(VM vm) {
		if(_coresBusy + vm.getCores() > _cores) {
			return false; // Cannot create VM here.
		}
		
		vm.setCurrentHost(this);
		vm.setHost(this);

		Subscription sub = vm.getSubscription();
		// Keep track of which Subscriptions have seen which other Subscriptions
		for(VM ovm : _currentVMs) {
			Subscription osub = ovm.getSubscription();
			if(!osub.equals(sub)) {
				osub.addSeenSubscription(vm.getSubscription());
				vm.getSubscription().addSeenSubscription(osub);
			}
		}

		_subsHosted.add(vm.getSubscription());
		Integer numSubVMs = _subVMsHosted.get(sub);
		if(numSubVMs == null) {
			numSubVMs = 1;
		} else {
			numSubVMs++;
		}
		_subVMsHosted.put(sub, numSubVMs);
		
		_currentVMs.add(vm);
		_allVMs.add(vm);
		
		for(int ms = 0 ; ms < _maliciousSets; ms++) {
			if(this.hasMaliciousVM(ms)) {
				vm.setWasColocatedWithMaliciousVM(ms, true);
			}

			if (vm.isMalicious(ms)) {
				if (!this.hasMaliciousVM(ms)) {
					_maliciousStart[ms].add(vm.getTimeCreated());

					for (VM hostvm : _currentVMs) {
						hostvm.setWasColocatedWithMaliciousVM(ms, true);
					}
				}
				_currentMaliciousVMs[ms]++;
			}
		}
		
		// update CU stats
		int time = vm.getTimeCreated();
		if(time < _lastEvent) {
			System.err.println("Error: Events out of order!");
			System.exit(1);
		} else {
			if(time > _lastEvent) {
				int timediff = time - _lastEvent;
				//_busyCoreTicks += timediff * _coresBusy;
				BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_coresBusy));
				_busyCoreTicks = _busyCoreTicks.add(coreTicks);
				_lastEvent = time;
			}

			if(time > _lastIntervalEvent) {
				int timediff = time - _lastIntervalEvent;
				BigInteger intCoreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_coresBusy));
				_intervalBusyCoreTicks = _intervalBusyCoreTicks.add(intCoreTicks);
				_lastIntervalEvent = time;
			}
		} // time == _lastEvent can be ignored, as no time has passed.

		_coresBusy += vm.getCores();
		_memoryUsed += vm.getMemory();
				
		return true;
	}

	/**
	 * 
	 * @return true if there is (still) a malicious VM on the Host.
	 */
	public void deleteVM(VM vm) {
		_currentVMs.remove(vm);

		vm.setCurrentHost(null);

		for(int ms = 0; ms < _maliciousSets; ms++) {
			if(vm.isMalicious(ms)) {
				_currentMaliciousVMs[ms]--;
				if(_currentMaliciousVMs[ms] == 0) {
					_maliciousEnd[ms].add(vm.getTimeDeleted());
				}
			}
		}

		Subscription sub = vm.getSubscription();
		Integer numSubVMs = _subVMsHosted.get(sub);
		numSubVMs--;
		if(numSubVMs == 0) {
			_subVMsHosted.remove(sub);
		} else {
			_subVMsHosted.put(sub, numSubVMs);
		}

		
		// update CU stats
		int time = vm.getTimeDeleted();
		if(time < _lastEvent) {
			System.err.println("Error: Events out of order!");
			System.exit(1);
		} else if(time > _lastEvent) {
			if(time > _lastEvent) {
				int timediff = time - _lastEvent;
				//_busyCoreTicks += (long)timediff * _coresBusy;
				BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_coresBusy));
				_busyCoreTicks = _busyCoreTicks.add(coreTicks);
				_lastEvent = time;
			}

			if (time > _lastIntervalEvent) {
				int timediff = time - _lastIntervalEvent;
				BigInteger intCoreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_coresBusy));
				_intervalBusyCoreTicks = _intervalBusyCoreTicks.add(intCoreTicks);
				_lastIntervalEvent = time;
			}
		} // time == _lastEvent can be ignored, as no time has passed.
		
		_coresBusy -= vm.getCores();
		_memoryUsed -= vm.getMemory();
	}
	
	public boolean boot(int time) {
		if(_booted >= 0) {
			return false; // already active
		} else {
			_booted = time;
			if(_numberOfBoots == 0) {
				_lastIntervalForTotalCoreTicks = time;
			}
			_numberOfBoots++;
			return true;
		}
	}

	public int numberOfBoots() {
		return _numberOfBoots;
	}

	public int freeCores() {
		return _cores - _coresBusy;
	}

	public double freeMemory() {
		return _memory - _memoryUsed;
	}
	
	/**
	 * 
	 * 
	 * @param time
	 * @return
	 */
	public boolean shutdown(int time) {
		if(_booted < 0) {
			return false; // already inactive
		} else if (time < _booted) {
			System.err.println("Error: Events out of order!");
			System.exit(1);
			return false;
		} else {
			if(_currentVMs.size() > 0) {
				return false; // Cannot shut down: still hosts VM(s).
			} else {
				int timediff = time - _booted;
				//_totalCoreTicks += (long)timediff * _cores;
				BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_cores));
				_totalCoreTicks = _totalCoreTicks.add(coreTicks);

				if(_booted < _lastIntervalForTotalCoreTicks) {
					timediff = time - _lastIntervalForTotalCoreTicks;
				}
				BigInteger intCoreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_cores));
				_intervalTotalCoreTicks = _intervalTotalCoreTicks.add(intCoreTicks);

				_booted = Integer.MIN_VALUE;

				return true;
			}
		}
	}
	
	public boolean hasMaliciousVM(int malSet) {
		return _currentMaliciousVMs[malSet] > 0;
	}

	public int[] getMaliciousPeriod(int index, int malSet) {
		if (index >= numberOfMaliciousPeriods(malSet)) {
			return null;
		}
				int[] out = new int[2];
				out[0] = _maliciousStart[malSet].get(index);
		if (index < _maliciousEnd[malSet].size()) {
			out[1] = _maliciousEnd[malSet].get(index);
		} else {
			out[1] = Integer.MAX_VALUE;
		}
		return out;
	}
	
	public int numberOfMaliciousPeriods(int malSet) {
		return _maliciousStart[malSet].size();
	}
	
	public boolean isActive() {
		return this._booted >= 0;
	}
	
	private BigInteger getTotalCoreTicks() {
		return this._totalCoreTicks;
	}
	
	public BigInteger getTotalCoreTicks(int time) {
		if(!isActive()) {
			return getTotalCoreTicks();
		} else {
			BigInteger totalTicks = getTotalCoreTicks();
			long timediff = time - _booted;
			//totalTicks += timediff * _cores;
			BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_cores));
			totalTicks = totalTicks.add(coreTicks);
			return totalTicks;
		}
	}

	public BigInteger getAndResetIntervalTotalCoreTicks(int time, int lastInterval) {
		BigInteger ret;
		if(!isActive()) {
			ret = _intervalTotalCoreTicks;
		} else {
			BigInteger totalTicks = _intervalTotalCoreTicks;
			long timediff = 0;
			if(_booted < lastInterval) {
				timediff = time - lastInterval;
			} else {
				timediff = time - _booted;
			}
			//totalTicks += timediff * _cores;
			BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_cores));
			totalTicks = totalTicks.add(coreTicks);

			ret = totalTicks;
		}

		_intervalTotalCoreTicks = BigInteger.ZERO;
		_lastIntervalForTotalCoreTicks = time;

		return ret;
	}
	
	private BigInteger getBusyCoreTicks() {
		return this._busyCoreTicks;
	}
	
	public BigInteger getBusyCoreTicks(int time) {
		if(!isActive()) {
			return getBusyCoreTicks();
		} else {
			BigInteger totalTicks = getBusyCoreTicks();
			long timediff = time - _lastEvent;
			//totalTicks += timediff * _coresBusy;
			BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_coresBusy));
			totalTicks = totalTicks.add(coreTicks);
			return totalTicks;
		}
	}

	public BigInteger getAndResetIntervalBusyCoreTicks(int time) {
		BigInteger ret;
		if(!isActive()) {
			ret = _intervalBusyCoreTicks;
		} else {
			BigInteger totalTicks = _intervalBusyCoreTicks;
			long timediff = time - _lastIntervalEvent;
			//totalTicks += timediff * _coresBusy;
			BigInteger coreTicks = BigInteger.valueOf(timediff).multiply(BigInteger.valueOf(_coresBusy));
			totalTicks = totalTicks.add(coreTicks);
			ret = totalTicks;
		}

		_intervalBusyCoreTicks = BigInteger.ZERO;
		_lastIntervalEvent = time;

		return ret;
	}

	public ArrayList<VM> getCurrentVMs() {
		//return _currentVMs.toArray(new VM[0]);
		return _currentVMs;
	}

	public int numberOfCurrentVMs() {
		return _currentVMs.size();
	}

	public HashSet<Subscription> getSubscriptions() {
		HashSet<Subscription> subs = new HashSet<Subscription>();

		for(VM vm : _currentVMs) {
			Subscription sub = vm.getSubscription();
			subs.add(sub);
		}

		return subs;
	}

	public Set<Subscription> getCurrentSubscriptions() {
		return _subVMsHosted.keySet();
	}

	public boolean hasHostedSubscription(Subscription s) {
		return _subsHosted.contains(s);
	}

	public int numberOfSubscriptionsHosted () {
		return _subsHosted.size();
	}

	public boolean hasHostedMaliciousSubscription(int malSet) {
		return _maliciousStart[malSet].size()>0;
	}

	public int getHostNumber() {
		return _hostNumber;
	}

	@Override
	public int hashCode() {
		return _hostNumber;
	}

	@Override
	public boolean equals(Object obj) {
		return _hostNumber == ((Host)obj)._hostNumber;
	}

	@Override
	public String toString() {
		return "Host " + _hostNumber + " (" + _coresBusy + "/" + _cores +  " cores, " + _memoryUsed + "/" + _memory + " GiB memory)";
	}
}