// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Class for parsing input CSV files for a simulation
 *
 * @author Jens Lindemann
 */
public class FileParser {
	// list of VMs in order of creation
	private HashMap<String,VM> _vms;
	// list of subscriptions
	private HashMap<String,Subscription> _subscriptions;
	// list of deployments
	private HashMap<String,Deployment> _deployments;

	public FileParser(File vmFile, int minTime, int maxTime, int maliciousSets) {
		this(vmFile, minTime, maxTime, maliciousSets, false);
	}

	public FileParser(File vmFile, int minTime, int maxTime, int maliciousSets, boolean dataIncludesTargets) {
		// Do *not* parse Subscriptions from File - This would load too many Subscriptions if only a part of the
		// period covered in the dataset is used in the simulation.
		//_subscriptions = parseSubscriptionFile(subscriptionFile);
		_subscriptions = new HashMap<String,Subscription>();
		//_deployments = parseDeploymentFile(deploymentFile);
		_vms = parseVMFile(vmFile, minTime, maxTime, maliciousSets, dataIncludesTargets);
	}

	// The following is not really needed and has thus been commented out: Subscriptions can also be parsed directly
	// from the VM file.
	/*private HashMap<String,Subscription> parseSubscriptionFile(File file) {
		HashMap<String,Subscription> subs = new HashMap<String,Subscription>();
				
		Scanner sc;
		try {
			sc = new Scanner(file);
			sc.useDelimiter("[,\\r\\n]+");

			while(sc.hasNext()) {
				String id = sc.next();
				int timeFirstVMCreated = sc.nextInt();
				int numVMs = sc.nextInt();
				
				Subscription sub = new Subscription(id, timeFirstVMCreated, numVMs);
				subs.put(id, sub);
			}
			
			sc.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.exit(1);
		}
		
		return subs;
	}*/

	private HashMap<String,Deployment> parseDeploymentFile(File file) {
		HashMap<String,Deployment> deps = new HashMap<String,Deployment>();
				
		Scanner sc;
		try {
			sc = new Scanner(file);
			sc.useDelimiter("[,\\r\\n]+");

			while(sc.hasNext()) {
				String id = sc.next();
				int numVMs = sc.nextInt();
				
				Deployment dep = new Deployment(id, numVMs);
				deps.put(id, dep);
			}
			
			sc.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.exit(1);
		}
		
		return deps;
	}

	private HashMap<String,VM> parseVMFile(File file, int minTime, int maxTime, int maliciousSets, boolean dataIncludesTargets) {
		HashMap<String,VM> vms = new HashMap<String,VM>();
				
		Scanner sc;
		try {
			sc = new Scanner(file);
			sc.useDelimiter("[,\\r\\n]+");

			while(sc.hasNext()) {
				String id = sc.next();
				String subID = sc.next();
				String deploymentID = sc.next(); 
				int timeCreated = sc.nextInt();
				int timeDeleted = sc.nextInt();
				double maxCPU = sc.nextDouble();
				double avgCPU = sc.nextDouble();
				double p95CPU = sc.nextDouble();
				String vmCategory = sc.next();
				String coresString = sc.next();
				if(coresString.contains(">")) {
					sc.next(); // Skip memory entry
					continue;
				}
				int cores = Integer.parseInt(coresString);
				String memoryString = sc.next();
				if(memoryString.contains(">")) {
					continue;
				}
				double memory = Double.parseDouble(memoryString);

				String targetVmId = null;
				if(dataIncludesTargets) {
					targetVmId = sc.next();
				}

				// Ignore VMs created or deleted outwith specified period
				if(timeCreated < minTime || timeDeleted > maxTime) {
					continue;
				}
				
				Subscription sub = getSubscription(subID);
				if(sub == null) {
					// This assumes that the events in the file are in order!
					sub = new Subscription(subID, timeCreated, maliciousSets);
					_subscriptions.put(subID, sub);
				};
				//Deployment deployment = getDeployment(deploymentID);

				VM vm;
				if(dataIncludesTargets) {
					vm = new VM(id, sub, timeCreated, timeDeleted, maxCPU, avgCPU, p95CPU, vmCategory, cores, memory, maliciousSets, targetVmId);
				} else {
					vm = new VM(id, sub, timeCreated, timeDeleted, maxCPU, avgCPU, p95CPU, vmCategory, cores, memory, maliciousSets);
				}

				
				// Check whether the dataset contains duplicate VM ids.
				if(vms.containsKey(id)) {
					System.err.println("Duplicate VM id!");
					System.exit(1);
				}
				
				vms.put(id, vm);
			}
			
			sc.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.exit(1);
		}
		
		return vms;
	}
	
	private VM getVM(String id) {
		return _vms.get(id);
	}
	
	private Subscription getSubscription(String id) {
		return _subscriptions.get(id);
	}
	
	/*private Deployment getDeployment(String id) {
		return _deployments.get(id);
	}*/
	
	public VM[] getVMsSortedByCreation() {
		List<VM> sorted = _vms.values().stream().sorted(Comparator.comparingInt(VM::getTimeCreated)).collect(Collectors.toList());
		return sorted.toArray(new VM[0]);
	}
	
	public VM[] getVMsSortedByDeletion() {
		List<VM> sorted = _vms.values().stream().sorted(Comparator.comparingInt(VM::getTimeDeleted)).collect(Collectors.toList());
		return sorted.toArray(new VM[0]);
	}

	public Collection<VM> getVMs() {
		return _vms.values();
	}

	public HashMap<String,VM> getVMHashMap() {
		return _vms;
	}

	public HashMap<String,Subscription> getSubscriptions() {
		return _subscriptions;
	}

	/*public HashMap<String,Deployment> getDeployments () {
		return _deployments;
	}*/
}