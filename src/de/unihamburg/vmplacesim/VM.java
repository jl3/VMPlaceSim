// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

/**
 * This class represents a VM in the simulation.
 *
 * @author Jens Lindemann
 */
public class VM {
	private String _id;
	private Subscription _subscription;
	//private Deployment _deployment;
	private int _timeCreated;
	private int _timeDeleted;
	private double _maxCPU;
	private double _avgCPU;
	private double _p95CPU;
	private String _vmCategory;
	private int _cores;
	private double _memory;
	private String _targetVmId;
	private VM _targetVM;
	private boolean _hitTarget;
	
	private boolean[] _wasColocatedWithMaliciousVM;
	private Host _currentHost;
	private Host _host;

	private int _maliciousSets;

	public VM(String id, Subscription sub, int timeCreated, int timeDeleted, double maxCPU,
			  double avgCPU, double p95CPU, String vmCategory, int cores, double memory, int maliciousSets) {
		this(id, sub, timeCreated, timeDeleted, maxCPU, avgCPU, p95CPU, vmCategory, cores, memory, maliciousSets, null);
	}

	public VM(String id, Subscription sub, int timeCreated, int timeDeleted, double maxCPU,
			double avgCPU, double p95CPU, String vmCategory, int cores, double memory, int maliciousSets,
			  String targetVmId) {
		this._id = id;
		this._subscription = sub;
		//this._deployment = deployment;
		this._timeCreated = timeCreated;
		this._timeDeleted = timeDeleted;
		this._maxCPU = maxCPU;
		this._avgCPU = avgCPU;
		this._p95CPU = p95CPU;
		this._vmCategory = vmCategory;
		this._cores = cores;
		this._memory = memory;
		this._maliciousSets = maliciousSets;
		this._targetVmId = targetVmId;
		this._hitTarget = false;

		this._wasColocatedWithMaliciousVM = new boolean[maliciousSets];
		this._currentHost = null;
		this._host = null;

		// Add target to subscription if VM has a target.
		if(_targetVM != null) {
			_subscription.addTarget(this);
		}
	}
	
	/**
	 * Returns whether the VM is malicious.
	 * For the time being, we will assume that the VMs of a subscription
	 * are either all benign or all malicious.
	 * @return true if the VM is malicious, false if the VM is benign
	 */
	public boolean isMalicious(int malSet) {
		return this._subscription.isMalicious(malSet);
	}
	
	public void setWasColocatedWithMaliciousVM(int malSet, boolean colocatedWithMaliciousVM) {
		_wasColocatedWithMaliciousVM[malSet] = colocatedWithMaliciousVM;
	}
	
	public boolean wasColocatedWithMaliciousVM(int malSet) {
		return this._wasColocatedWithMaliciousVM[malSet];
	}
	
	public void setCurrentHost(Host h) {
		_currentHost = h;
	}

	public Host getCurrentHost() {
		return _currentHost;
	}

	public void setHost(Host h) {
		_host = h;
	}

	public Host getHost() {
		return _host;
	}
	
	/**
	 * @return the _id
	 */
	public String getID() {
		return _id;
	}

	/**
	 * @return the _subscription
	 */
	public Subscription getSubscription() {
		return _subscription;
	}

	public void setSubscription(Subscription newSubscription) {
		this._subscription = newSubscription;
	}

	/*
	 * @return the _deployment
	 */
	/*public Deployment getDeployment() {
		return _deployment;
	}*/

	/**
	 * @return the _timeCreated
	 */
	public int getTimeCreated() {
		return _timeCreated;
	}

	/**
	 * @return the _timeDeleted
	 */
	public int getTimeDeleted() {
		return _timeDeleted;
	}

	/**
	 * @return the _maxCPU
	 */
	public double getMaxCPU() {
		return _maxCPU;
	}

	/**
	 * @return the _avgCPU
	 */
	public double getAvgCPU() {
		return _avgCPU;
	}

	/**
	 * @return the _p95CPU
	 */
	public double getP95CPU() {
		return _p95CPU;
	}

	/**
	 * @return the _vmCategory
	 */
	public String getVMCategory() {
		return _vmCategory;
	}

	/**
	 * @return the _cores
	 */
	public int getCores() {
		return _cores;
	}

	/**
	 * @return the _memory
	 */
	public double getMemory() {
		return _memory;
	}

	/**
	 *
	 * @return true if VM has a target, false otherwise
	 */
	public boolean hasTarget() {
		return _targetVmId != null;
	}

	public String getTargetVmId() {
		return _targetVmId;
	}

	public void initialiseTargetRef(VM targetVm) {
		_targetVM = targetVm;
	}

	public VM getTargetVM() {
		return _targetVM;
	}

	public Subscription getTargetSubscription() {
		if(this.hasTarget()) {
			return _targetVM.getSubscription();
		} else {
			return null;
		}
	}

	public void setTargetHit() {
		_hitTarget = true;

		// TODO An alternative approach would be to record a hit on a different target of a Subscription,
		// even if it does not match the VM's target.
		_subscription.recordHit(_targetVM);
		_subscription.recordHit(_targetVM.getSubscription());
	}

	public boolean hasHitTarget() {
		return _hitTarget;
	}

	@Override
	public boolean equals(Object obj) {
		// This assumes that IDs are unique.
		return _id.equals(((VM)obj)._id);
	}
	
	@Override
	public int hashCode() {
		return _id.hashCode();
	}

	@Override
	public String toString() {
		String str = "VM " + _id + " (cores " + _cores + ", memory " + _memory + ", created " + _timeCreated
				+ ", deleted " + _timeDeleted  + ", " + _memory + " GiB memory" + ", subscription " + _subscription.getID()
				+ ", max CPU " + _maxCPU + ", average CPU " + _avgCPU
				+ "p95 CPU " + _p95CPU + ", VM category " + _vmCategory + ")";
		return str;
	}
}