// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.util.HashSet;

/**
 * This class represents a deployment. A deployment has an ID and VMs can be associated with it.
 *
 * @author Jens Lindemann
 */
public class Deployment {
	private String _id;
	private int _numVMs;
	private HashSet<VM> _currentVMs;
	private HashSet<VM> _totalVMs;

	public Deployment(String id, int numVMs) {
		this._id = id;
		this._numVMs = numVMs;
		
		_currentVMs = new HashSet<VM>();
		_totalVMs = new HashSet<VM>();
	}
	
	public void createVM(VM vm) {
		_currentVMs.add(vm);
		_totalVMs.add(vm);
	}
	
	public void deleteVM(VM vm) {
		_totalVMs.remove(vm);
	}
	
	public VM[] getCurrentVMs() {
		return _currentVMs.toArray(new VM[0]);
	}
	
	public VM[] getTotalVMs() {
		return _totalVMs.toArray(new VM[0]);
	}

	/**
	 * @return the _id
	 */
	public String getID() {
		return _id;
	}

	/**
	 * @return the _numVMs
	 */
	public int getNumVMs() {
		return _numVMs;
	}

	@Override
	public boolean equals(Object obj) {
		// This assumes that IDs are unique.
		return _id.equals(obj);
	}

	@Override
	public int hashCode() {
		return _id.hashCode();
	}

	@Override
	public String toString() {
		String str = "Deployment " + _id + " (current VMs: " + _currentVMs + ", total VMs " + _totalVMs; 
		return str;
	}

}