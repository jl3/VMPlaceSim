// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.*;

/**
 * This class represents a subscription of a user in the simulation.
 *
 * @author Jens Lindemann
 */
public class Subscription {
	private String _id;
	private int _timeFirstVMCreated;
	private int _numVMs;
	private HashSet<VM> _currentVMs;
	private HashSet<VM> _totalVMs;
	private boolean[] _malicious;

	private HashSet<Subscription> _seenSubs;
	private HashMap<Subscription, Boolean> _targetSubscriptions;
	private HashMap<VM, Boolean> _targetVMs;

	private Hashtable<Subscription, Integer> _coresidentTime;
	private Hashtable<Subscription, Integer> _currentlyCoresSubs;
	private int _lastCoresUpdateTime;
	private int _activeTime;
	private int _activeTimeUpdated;
	private boolean[] _exposedToMaliciousSubs;

	public Subscription(String id, int timeFirstVMCreated, int maliciousSets) {
		this._id = id;
		this._timeFirstVMCreated = timeFirstVMCreated;
		this._numVMs = 0;
		_malicious = new boolean[maliciousSets];
		
		this._currentVMs = new HashSet<VM>();
		this._totalVMs = new HashSet<VM>();
		this._seenSubs = new HashSet<Subscription>();

		this._targetSubscriptions = new HashMap<Subscription, Boolean>();
		this._targetVMs = new HashMap<VM, Boolean>();

		_coresidentTime = new Hashtable<Subscription, Integer>();
		_currentlyCoresSubs = new Hashtable<Subscription, Integer>();
		_lastCoresUpdateTime = timeFirstVMCreated;
		_activeTime = 0;
		_activeTimeUpdated = Integer.MIN_VALUE;
		_exposedToMaliciousSubs = new boolean[maliciousSets];
	}
	
	public void createVM(VM vm) {
		if(_currentVMs.size() == 0) {
			_activeTimeUpdated = vm.getTimeCreated();
		}

		_currentVMs.add(vm);
		_totalVMs.add(vm);
		_numVMs++;
	}
	
	public void deleteVM(VM vm) {
		_currentVMs.remove(vm);

		if(_currentVMs.size() == 0) {
			int newTime = vm.getTimeDeleted();
			int timediff = newTime - _activeTimeUpdated;
			_activeTime += timediff;
			_activeTimeUpdated = newTime;
		}
	}
	
	public boolean wasExposedToMaliciousSub(int malSet) {
		return _exposedToMaliciousSubs[malSet];
	}
	
	public VM[] getCurrentVMs() {
		return _currentVMs.toArray(new VM[0]);
	}

	public Host[] getCurrentHosts() {
		HashSet<Host> currentHosts = new HashSet<Host>();
		for(VM vm : _currentVMs) {
			currentHosts.add(vm.getCurrentHost());
		}
		return currentHosts.toArray(new Host[0]);
	}
	
	public HashSet<VM> getTotalVMs() {
		//return _totalVMs.toArray(new VM[0]);
		return _totalVMs;
	}
	
	public void setMalicious(int malSet, boolean malicious) {
		this._malicious[malSet] = malicious;
	}
	
	public boolean isMalicious(int malSet) {
		return this._malicious[malSet];
	}

	/**
	 * @return the _id
	 */
	public String getID() {
		return _id;
	}

	/**
	 * @return the _timeFirstVMCreated
	 */
	public int getTimeFirstVMCreated() {
		return _timeFirstVMCreated;
	}

	/**
	 * @return the _numVMs
	 */
	public int getNumberOfVMs() {
		return _numVMs;
	}

	@Override
	public boolean equals(Object obj) {
		// This assumes that IDs are unique.
		return _id.equals(((Subscription)obj)._id);
	}
	
	@Override
	public int hashCode() {
		return _id.hashCode();
	}

	@Override
	public String toString() {
		String str = "Subscription " + _id + " (current VMs " + _currentVMs + ", total VMs " + _currentVMs + ", first VM created " + _timeFirstVMCreated;
		return str;
	}

	public HashSet<Subscription> getSeenSubscriptions() {
		return _seenSubs;
	}

	public void addSeenSubscription(Subscription subscription) {
		_seenSubs.add(subscription);
		for(int i = 0; i < _exposedToMaliciousSubs.length; i++) {
			if(subscription.isMalicious(i)) {
				_exposedToMaliciousSubs[i] = true;
			}
		}
	}

	public boolean hasSeenSubscription(Subscription subscription) {
		return this.equals(subscription) || _seenSubs.contains(subscription);
	}

	public boolean hasHitTarget(Subscription sub) {
		return _targetSubscriptions.get(sub);
	}

	public boolean hasHitTarget(VM vm) {
		return _targetVMs.get(vm);
	}

	public void addTarget(VM vm) {
		// add VM to targets
		if(_targetVMs.get(vm) == null) {
			_targetVMs.put(vm, false);
		}

		// add corresponding Subscription to targets
		Subscription sub = vm.getSubscription();
		if(_targetSubscriptions.get(sub) == null) {
			_targetSubscriptions.put(sub, false);
		}
	}

	public void recordHit(VM vm) {
		_targetVMs.put(vm, true);
	}

	public void recordHit(Subscription sub) {
		_targetSubscriptions.put(sub, true);
	}

	public int numberOfTargetVMs() {
		return _targetVMs.size();
	}

	public int numberOfTargetSubscriptions() {
		return _targetSubscriptions.size();
	}

	public int numberOfHitTargetVMs() {
		int totalHitTargetVMs = 0;
		for(Map.Entry<VM, Boolean> ent: _targetVMs.entrySet()) {
			if(ent.getValue().booleanValue() == true) {
				totalHitTargetVMs++;
			}
		}
		return totalHitTargetVMs;
	}

	public double proportionOfHitTargetVMs() {
		double prop = -1;
		if(this.numberOfTargetVMs() > 0) {
			prop = this.numberOfHitTargetVMs() / this.numberOfTargetVMs();
		}
		return prop;
	}

	public int numberOfHitTargetSubscriptions() {
		int totalHitTargetSubs = 0;
		for (Map.Entry<Subscription, Boolean> ent : _targetSubscriptions.entrySet()) {
			if (ent.getValue().booleanValue() == true) {
				totalHitTargetSubs++;
			}
		}
		return totalHitTargetSubs;
	}

	public double proportionOfHitTargetSubscriptions() {
		double prop = -1;
		if(this.numberOfTargetSubscriptions() > 0) {
			prop = this.numberOfTargetSubscriptions() / this.numberOfTargetVMs();
		}
		return prop;
	}

	/**
	 * This should be called *before* a VM of the Subscription is called/deleted.
	 * @param time
	 */
	protected void updateCoresidenceStats(int time) {
		int timediff = _lastCoresUpdateTime - time;
		if(timediff == 0) {
			return;
		}

		if(_currentVMs.size() > 0) {
			_activeTime += timediff;
			_activeTimeUpdated = time;
		}

		Enumeration<Subscription> coresSubs = _currentlyCoresSubs.keys();
		while(coresSubs.hasMoreElements()) {
			Subscription otherSub = coresSubs.nextElement();

			if(_coresidentTime.containsKey(otherSub)) {
				int value = _coresidentTime.get(otherSub);
				value += timediff;
				_coresidentTime.put(otherSub, value);
			} else {
				_coresidentTime.put(otherSub, timediff);
			}
		}
	}

	protected void addCoresidentVM(VM vm) {
		Subscription otherSub = vm.getSubscription();
		if(otherSub.equals(this)) {
			return;
		}
		if(_currentlyCoresSubs.containsKey(otherSub)) {
			int numVMs = _currentlyCoresSubs.get(otherSub);
			numVMs++;
			_currentlyCoresSubs.put(otherSub, numVMs);
		} else {
			_currentlyCoresSubs.put(otherSub, 1);
		}
	}

	protected void removeCoresidentVM(VM vm) {
		Subscription otherSub = vm.getSubscription();
		if(otherSub.equals(this)) {
			return;
		}
		int numVMs = _currentlyCoresSubs.get(otherSub);
		numVMs--;
		if(numVMs == 0) {
			_currentlyCoresSubs.remove(otherSub);
		} else {
			_currentlyCoresSubs.put(otherSub, numVMs);
		}
	}

	protected int getCoresidentTime(Subscription subscription) {
		if (subscription.equals(this)) {
			return _activeTime;
		} else {
			Integer corestime = _coresidentTime.get(subscription);
			if(corestime == null) {
				return 0;
			} else {
				return corestime;
			}
		}
	}

	protected int numberOfSubscriptionsSeen() {
		return _seenSubs.size();
	}

	protected int getActiveTime() {
		return _activeTime;
	}
}