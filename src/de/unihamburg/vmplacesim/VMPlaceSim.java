// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import org.apache.commons.cli.*;

import java.io.*;
import java.math.BigDecimal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Main class of the simulation framework. Provides a CLI interface, parses the input files,
 * runs the simulation and outputs the statistics.
 *
 * @author Jens Lindemann
 */
public abstract class VMPlaceSim {
	public static void main (String[] args) {
		Options opt = new Options();

		// define CLI options
		Option vmFileOpt = Option.builder("v")
				.longOpt("vmfile")
				.hasArg()
				.argName("file")
				.desc("VM csv file (default: vmtable.csv)")
				.build();

		Option maliciousSubsOpt = Option.builder("ms")
				.longOpt("malsubs")
				.hasArg()
				.argName("proportion")
				.desc("comma-separated list of the proportions of malicious subscriptions (default: 0.05)")
				.build();

		Option maliciousSubDataOpt = Option.builder("msd")
				.longOpt("malsubdata")
				.hasArg()
				.argName("files")
				.desc("comma-separated list of CSV files containing VM requests of malicious subscriptions. If no "
					+ "other malicious subscriptions are desired, the ms parameter should be set to 0.00.")
				.build();

		Option maliciousSubDataHasTargetsOpt = Option.builder("msdt")
				.longOpt("malsubdatahastargets")
				.desc("parse targets from malsubdata files")
				.build();

		Option maliciousSubDataReplaceIDOpt = Option.builder("msdrid")
				.longOpt("malsubdatareplaceid")
				.hasArg()
				.argName("subscription id")
				.desc("Replace subscription ID of malicious VMs loaded from malicious subscription data files")
				.build();

		Option noMaleventsOpt = Option.builder("nomalevents")
				.desc("Do not output malicious events to file")
				.build();

		Option hostsOpt = Option.builder("n")
				.longOpt("hosts")
				.hasArg()
				.argName("number")
				.desc("sets the number of hosts (default: 200000)")
				.build();

		Option coresPerHostOpt = Option.builder("c")
				.longOpt("cores")
				.hasArg()
				.argName("number")
				.desc("sets the number of cores per host (default: 32)")
				.build();

		Option memPerHostOpt = Option.builder("m")
				.longOpt("memory")
				.hasArg()
				.argName("number")
				.desc("sets the amount of memory per host (default: 224 (GiB))")
				.build();

		Option algorithmOpt = Option.builder("a")
				.longOpt("alg")
				.required()
				.hasArg()
				.argName("algorithm")
				.desc("sets the placement strategy to use (available strategies:  Azar, BestFit, ¨" +
						"DedicatedInstance, FirstFit, Han, HanKeepOn, KnownUsers, KnownUsers-LowestAvgSeen, KnownVMs," +
						" KnownVMs-LowestAvgSeen, LDBR, NextFit, PCUF, RandomActive, WorstFit")
				.build();

		Option rndSeedOpt = Option.builder("s")
				.longOpt("seed")
				.hasArg()
				.argName("seed")
				.desc("sets the seed")
				.build();

		Option activeHostsOpt = Option.builder("b")
				.longOpt("activehosts")
				.hasArg()
				.argName("number of hosts")
				.desc("number of hosts intially active (default: 0)")
				.build();

		Option minTimeOpt = Option.builder("tmin")
				.longOpt("mintime")
				.hasArg()
				.argName("time")
				.desc("sets the minimum time")
				.build();

		Option maxTimeOpt = Option.builder("tmax")
				.longOpt("maxtime")
				.hasArg()
				.argName("time")
				.desc("sets the maximum time")
				.build();

		Option outputFileOpt = Option.builder("o")
				.longOpt("output")
				.hasArg()
				.argName("file")
				.desc("filename prefix for CSV output of results")
				.build();

		Option maxCoresOpt = Option.builder("mc")
				.longOpt("maxcores")
				.hasArg()
				.argName("number of cores")
				.desc("maximum number of cores for a VM (for Azar strategy)")
				.build();

		Option maxMemoryOpt = Option.builder("mm")
				.longOpt("maxmem")
				.hasArg()
				.argName("amount (GiB)")
				.desc("maximum memory in GiB for a VM (for Azar strategy)")
				.build();

		Option nstarOpt = Option.builder("nstar")
				.longOpt("maxsubvmonhost")
				.hasArg()
				.argName("number of hosts")
				.desc("n star parameter (max. number of VMs of the same subscription on a host, default: 4)")
				.build();

		Option statIntervalOpt = Option.builder("si")
				.longOpt("statinterval")
				.hasArg()
				.argName("interval")
				.desc("interval for stat output (default: 21600 (6 hours))")
				.build();

		Option statMinTimeOpt = Option.builder("smt")
				.longOpt("statmintime")
				.hasArg()
				.argName("time")
				.desc("sets the minimum time for stats (default: minimum time for simulation)")
				.build();

		Option pertModeOpt = Option.builder("pertmode")
				.hasArg()
				.argName("mode")
				.desc("sets the mode of the PERT distribution used in the LDBR strategy for malicious " +
						"subscriptions (must be <1.0, default: 0.9)")
				.build();

		Option pertLambdaOpt = Option.builder("pertlambda")
				.hasArg()
				.argName("lambda")
				.desc("sets the lambda of the PERT distribution used in the LDBR strategy (default: 3.0)")
				.build();

		Option helpOpt = Option.builder("h")
				.longOpt("help")
				.desc("print this message")
				.build();

		// add CLI options
		opt.addOption(vmFileOpt);
		opt.addOption(maliciousSubsOpt);
		opt.addOption(maliciousSubDataOpt);
		opt.addOption(maliciousSubDataHasTargetsOpt);
		opt.addOption(maliciousSubDataReplaceIDOpt);
		opt.addOption(noMaleventsOpt);
		opt.addOption(hostsOpt);
		opt.addOption(coresPerHostOpt);
		opt.addOption(memPerHostOpt);
		opt.addOption(algorithmOpt);
		opt.addOption(rndSeedOpt);
		opt.addOption(activeHostsOpt);
		opt.addOption(minTimeOpt);
		opt.addOption(maxTimeOpt);
		opt.addOption(outputFileOpt);
		opt.addOption(maxCoresOpt);
		opt.addOption(maxMemoryOpt);
		opt.addOption(nstarOpt);
		opt.addOption(statIntervalOpt);
		opt.addOption(statMinTimeOpt);
		opt.addOption(pertModeOpt);
		opt.addOption(pertLambdaOpt);
		opt.addOption(helpOpt);

		// parse CLI parameters
		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(opt, args);

			if(cmd.hasOption(helpOpt.getOpt())) {
				printHelp(opt);
			}

			// parse vmFileOpt
			String vmFilename = "vmtable.csv";
			if(cmd.hasOption(vmFileOpt.getOpt())) {
				vmFilename = cmd.getOptionValue(vmFileOpt.getOpt());
			}
			File vmFile = new File(vmFilename);

			// Initialise Random. Use seed from CLI, if one was specified.
			Random rnd;
			long seed = 0; // This is needed for the CSV output. 0 will never be used, unless explicitly passed to the CLI.
			if(cmd.hasOption(rndSeedOpt.getOpt())) {
				seed = Long.parseLong(cmd.getOptionValue(rndSeedOpt.getOpt()));
				rnd = new Random(seed+1); // use seed+1 here, so that we don't use exactly the same seed as for declaring Subscriptions malicious...
			} else {
				// Use a random seed
				rnd = new Random();
			}

			// pase numHostsOpt (int)
			int numHosts = 200000;
			if(cmd.hasOption(hostsOpt.getOpt())) {
				numHosts = Integer.parseInt(cmd.getOptionValue(hostsOpt.getOpt()));
			}

			// parse activeHostsOpt (int)
			int numActiveHosts = 0;
			if(cmd.hasOption(activeHostsOpt.getOpt())) {
				numActiveHosts = Integer.parseInt(cmd.getOptionValue(activeHostsOpt.getOpt()));
			}

			// parse coresPerHostOpt (int)
			int coresPerHost = 32;
			if(cmd.hasOption(coresPerHostOpt.getOpt())) {
				coresPerHost = Integer.parseInt(cmd.getOptionValue(coresPerHostOpt.getOpt()));
			}

			// parse memoryPerHostOpt (double)
			int memPerHost = 224;
			if(cmd.hasOption(memPerHostOpt.getOpt())) {
				memPerHost = Integer.parseInt(cmd.getOptionValue(memPerHostOpt.getOpt()));
			}

			// parse minTimeOpt (int)
			int minTime = Integer.MIN_VALUE;
			if(cmd.hasOption(minTimeOpt.getOpt())) {
				minTime = Integer.parseInt(cmd.getOptionValue(minTimeOpt.getOpt()));
			}

			// parse maxTimeOpt (int)
			int maxTime = Integer.MAX_VALUE;
			if(cmd.hasOption(maxTimeOpt.getOpt())) {
				maxTime = Integer.parseInt(cmd.getOptionValue(maxTimeOpt.getOpt()));
			}

			// parse maxCoresOpt (int)
			int maxCores = 16;
			if(cmd.hasOption(maxCoresOpt.getOpt())) {
				maxTime = Integer.parseInt(cmd.getOptionValue(maxCoresOpt.getOpt()));
			}

			// parse maxMemoryOpt (double)
			double maxMemory = 112;
			if(cmd.hasOption(maxMemoryOpt.getOpt())) {
				maxMemory = Double.parseDouble(cmd.getOptionValue(maxMemoryOpt.getOpt()));
			}

			// parse nstarOpt (int)
			int nstar = 4;
			if(cmd.hasOption(nstarOpt.getOpt())) {
				nstar = Integer.parseInt(cmd.getOptionValue(nstarOpt.getOpt()));
			}

			// parse statIntervalOpt (int)
			int statInterval = 21600;
			if(cmd.hasOption(statIntervalOpt.getOpt())) {
				statInterval = Integer.parseInt(cmd.getOptionValue(statIntervalOpt.getOpt()));
			}

			// parse statMinTimeOpt (int)
			int statMinTime = minTime;
			if(cmd.hasOption(statMinTimeOpt.getOpt())) {
				statMinTime = Integer.parseInt(cmd.getOptionValue(statMinTimeOpt.getOpt()));
			}

			// parse maliciousSubsOpt (double, proportion of malicious subs)
			double[] malsubProp = {0.05};
			if(cmd.hasOption(maliciousSubsOpt.getOpt())) {
				String[] malsubPropStrings = cmd.getOptionValue(maliciousSubsOpt.getOpt()).split(",");
				malsubProp = new double[malsubPropStrings.length];
				for(int i = 0; i < malsubProp.length; i++) {
					malsubProp[i] = Double.parseDouble(malsubPropStrings[i]);
				}
			}

			// parse maliciousSubDataOpt (String, filenames for CSVs containing malicious VM requests)
			File[] malsubDataFiles = null;
			if(cmd.hasOption(maliciousSubDataOpt.getOpt())){
				String[] malsubDataFilenames = cmd.getOptionValue(maliciousSubDataOpt.getOpt()).split(",");
				malsubDataFiles = new File[malsubDataFilenames.length];
				for(int i = 0; i < malsubDataFilenames.length; i++) {
					malsubDataFiles[i] = new File(malsubDataFilenames[i]);
				}
			}

			// parse maliciousSubDataHasTargetsOpt (boolean)
			boolean maliciousSubDataHasTargets = false;
			if(cmd.hasOption(maliciousSubDataHasTargetsOpt.getOpt())) {
				maliciousSubDataHasTargets = true;
			}

			// parse maliciousSubDataReplaceIDOpt (String)
			String replaceMalSubDataIDStr = null;
			if(cmd.hasOption(maliciousSubDataReplaceIDOpt.getOpt())) {
				replaceMalSubDataIDStr = cmd.getOptionValue(maliciousSubDataReplaceIDOpt.getOpt());
			}

			// parse noMaleventsOpt (boolean)
			boolean noMalevents = false;
			if(cmd.hasOption(noMaleventsOpt.getOpt())) {
				noMalevents = true;
			}

			// parse pertModeOpt (double)
			double pertMode = 0.9;
			if(cmd.hasOption(pertModeOpt.getOpt())) {
				pertMode = Double.parseDouble(cmd.getOptionValue(pertModeOpt.getOpt()));
			}

			// parse pertLambdaOpt (double)
			double pertLambda = 3;
			if(cmd.hasOption(pertLambdaOpt.getOpt())) {
				pertLambda = Double.parseDouble(cmd.getOptionValue(pertLambdaOpt.getOpt()));
			}

			// call FileParser, grab VM, Deployment, Subscriptions
			System.out.println("Parsing input files...");
			FileParser fparser = new FileParser(vmFile, minTime, maxTime, malsubProp.length);
			HashSet<VM> parsedVMs = new HashSet<VM>(fparser.getVMs());
			//HashMap<String,Deployment> deployments = fparser.getDeployments();
			HashMap<String,Subscription> subscriptions = fparser.getSubscriptions();

			// Make Subscriptions malicious
			makeSubscriptionsMalicious(subscriptions.values().toArray(new Subscription[0]), malsubProp, seed);

			// Add malicious subscriptions from files
			Collection<VM> malSubDataVMs = null;
			HashSet<VM> maliciousVMs = new HashSet<VM>();
			if(malsubDataFiles != null) {
				for(File malsubDataFile : malsubDataFiles) {
					// parse files, extract VM requests
					FileParser malParser = new FileParser(malsubDataFile, minTime, maxTime, malsubProp.length, maliciousSubDataHasTargets);

					// Add to the list of parsed VMs
					malSubDataVMs = malParser.getVMs();
					maliciousVMs.addAll(malSubDataVMs);
					parsedVMs.addAll(malSubDataVMs);

					// extract Subscriptions, check for duplicates
					HashMap<String,Subscription> fileSubs = malParser.getSubscriptions();
					for(Map.Entry<String,Subscription> fileSubEntry : fileSubs.entrySet()) {
						String fileSubID = fileSubEntry.getKey();
						Subscription fileSub = fileSubEntry.getValue();

						// When creating subscription: Check whether ID already exists
						if(subscriptions.containsKey(fileSubID)) {
							// TODO This could also be handled by renaming.
							System.err.println("Error: Subscription ID " + fileSubID + "already exists!");
							System.exit(-1);
						}

						// Make Subscription malicious for all malsubProps
						for(int i = 0; i < malsubProp.length; i++) {
							fileSub.setMalicious(i, true);
						}

						subscriptions.put(fileSubID, fileSub);
					}
				}

				if(maliciousSubDataHasTargets) {
					HashMap<String,VM> normalVmMap = fparser.getVMHashMap();
					for(VM malVM : maliciousVMs) {
						VM targetVM = normalVmMap.get(malVM.getTargetVmId());
						malVM.initialiseTargetRef(targetVM);
					}
				}
			}

			VM[] vmCreations = sortVMsByCreation(parsedVMs);
			VM[] vmDeletions = sortVMsByDeletion(parsedVMs);

			// Replace subscription IDs of malicious VMs loaded from malicious data files.
			// Doing this after sorting the arrays by creation and deleetion time ensures that identically-ordered
			// arrays can be produced for experiments with constand vs. dynamic subscription IDs.
			if(replaceMalSubDataIDStr != null) {
				Subscription replacementSub = null;
				if(subscriptions.containsKey(replaceMalSubDataIDStr)) {
					replacementSub = subscriptions.get(replaceMalSubDataIDStr);
				} else {
					int timeFirstMaliciousVMCreated = Integer.MAX_VALUE;
					for(VM vm : maliciousVMs) {
						if(vm.getTimeCreated() < timeFirstMaliciousVMCreated) {
							timeFirstMaliciousVMCreated = vm.getTimeCreated();
						}
					}

					replacementSub = new Subscription(replaceMalSubDataIDStr, timeFirstMaliciousVMCreated, malsubProp.length);
					for(int i = 0; i < malsubProp.length; i++) {
						replacementSub.setMalicious(i, true);
					}
				}

				HashSet<Subscription> oldMaliciousSubs = new HashSet<Subscription>();
				for(VM vm : maliciousVMs) {
					Subscription oldSub = vm.getSubscription();
					oldMaliciousSubs.add(oldSub);
					vm.setSubscription(replacementSub);
				}

				// remove replaced subscriptions
				for(Subscription oldSub : oldMaliciousSubs) {
					subscriptions.remove(oldSub.getID());
				}
			}

			// Instantiate concrete PlacementAlgorithm subclass
			PlacementStrategy alg;
			String algclistr = cmd.getOptionValue(algorithmOpt.getOpt());
			String algstr = null;
			if(algclistr.equals("KnownVMs")) {
				algstr = "KV";
				alg = new KnownProportionStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, false, false, malsubProp.length);
			} else if(algclistr.equals("KnownVMs-LowestAvgSeen")) {
				algstr = "KV-LAvg";
				alg = new KnownProportionStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, false, true, malsubProp.length);
			} else if(algclistr.equals("KnownUsers")) {
				algstr = "KU";
				alg = new KnownProportionStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, true, false, malsubProp.length);
			} else if(algclistr.equals("KnownUsers-LowestAvgSeen")) {
				algstr = "KU-LAvg";
				alg = new KnownProportionStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, true, true, malsubProp.length);
			} else if(algclistr.equals("BestFit")) {
				algstr = "BestFit";
				alg = new BestFitStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			} else if(algclistr.equals("WorstFit")) {
				algstr = "WorstFit";
				alg = new WorstFitStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			} else if(algclistr.equals("FirstFit")) {
				algstr = "FirstFit";
				alg = new FirstFitStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			} else if(algclistr.equals("NextFit")) {
				algstr = "NextFit";
				alg = new NextFitStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			} else if(algclistr.equals("RandomActive")) {
				algstr = "Random";
				alg = new RandomActiveStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			} else if(algclistr.equals("DedicatedInstance")) {
				algstr = "DedInst";
				alg = new DedicatedInstanceStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			}  else if(algclistr.equals("Azar")) {
				algstr = "Azar";
				alg = new AzarStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, maxCores, maxMemory, malsubProp.length);
			} else if(algclistr.equals("HanKeepOn")) {
				algstr = "HanKeepOn";
				alg = new HanKeepOnStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, nstar, malsubProp.length);
			} else if(algclistr.equals("Han")) {
				algstr = "Han";
				alg = new HanStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, nstar, malsubProp.length);
			} else if(algclistr.equals("LDBR")) {
				algstr = "LDBR";
				alg = new LDBRStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length, malsubProp[0], pertMode, pertLambda, seed);
			} else if(algclistr.equals("AgarwalPCUF")) {
				algstr = "PCUF";
				alg = new AgarwalStrategy(numHosts, numActiveHosts, coresPerHost, memPerHost, rnd, minTime, statInterval, statMinTime, malsubProp.length);
			} else {
				System.err.println("ERROR: Unknown algorithm!");
				System.exit(-1);
				return;
			}

			// perform the actual simulation
			alg.simulatePlacements(vmCreations, vmDeletions);

			// get and output statistics
			BigDecimal coreUtilisation = alg.calculateCoreUtilisation();

			double[] userCLR = new double[malsubProp.length];
			double[] vmCLR = new double[malsubProp.length];
			double[] unsafeSubVmCLR = new double[malsubProp.length];
			BigDecimal[][] safeVMTimeProportion = new BigDecimal[malsubProp.length][2];
			BigDecimal[] safeSubTimeProportion = new BigDecimal[malsubProp.length];
			Subscription[] subs = subscriptions.values().toArray(new Subscription[0]);
			double[] totalCoverage = new double[malsubProp.length];
			Host[] hosts = alg._hosts;
			for(int i = 0; i < malsubProp.length; i++) {
				userCLR[i] = alg.calculateUserBasedCLR(subs, i);
				vmCLR[i] = PlacementStrategy.calculateVmBasedCLR(vmCreations, i);
				unsafeSubVmCLR[i] = PlacementStrategy.calculateUnsafeSubVmBasedCLR(vmCreations, i);
				safeVMTimeProportion[i] = PlacementStrategy.calculateSafeVMTimeProportion(vmCreations, i);
				safeSubTimeProportion[i] = PlacementStrategy.calculateSafeSubscriptionTimeProportion(subs, i);
				totalCoverage[i] = PlacementStrategy.calculateTotalCoverage(hosts, i);
			}

			int maxHosts = alg.getMaxHostsActive();
			int maxVMsActive = alg.getMaxVMsActive();
			BigDecimal avgVMsActive = alg.getAvgActiveVMs();
			BigDecimal avgHostsActive = alg.getAvgActiveHosts();
			int hostBoots = alg.getHostsBooted();
			int hostShutdowns = alg.getHostsShutDown();
			int totalSubKnownEntries = alg.getTotalSubKnownEntries();
			double avgSubsKnownPerSub = alg.getAvgSubsKnownPerSub();
			int totalSubsSeenByHosts = alg.getTotalSubsSeenByHosts();
			double avgSubsSeenPerHost = alg.getAvgSubsSeenPerHost();
			double avgHostsSeenPerSub = alg.getAvgHostsSeenPerSub();

			if(algstr != null) {
				System.out.println("Algorithm: " + algstr);
			}

			if(cmd.hasOption(rndSeedOpt.getOpt())) {
				System.out.println("Seed: " + cmd.getOptionValue(rndSeedOpt.getOpt()));
			}

			String malsubdataStr = "none";
			if(cmd.hasOption(maliciousSubDataOpt.getOpt())) {
				malsubdataStr = malsubDataFiles[0].getName();
				if(malsubdataStr.endsWith(".csv")) {
					malsubdataStr = malsubdataStr.substring(0, malsubdataStr.length()-4);
				}
			}

			System.out.println("Core Utilisation: " + coreUtilisation);
			//System.out.println("User-based CLR: " + userCLR);
			//System.out.println("VM-based CLR: " + vmCLR);
			System.out.println(""); // empty line

			// CSV output
			if(cmd.hasOption(outputFileOpt.getOpt())) {
				String sep = ";";
				String outstr = algstr + sep + seed + sep + malsubdataStr + sep + coreUtilisation + sep + avgHostsActive + sep + maxHosts + sep + hostBoots + sep + hostShutdowns + sep + vmCreations.length + sep + avgVMsActive + sep + maxVMsActive + sep + totalSubKnownEntries + sep + avgSubsKnownPerSub + sep + totalSubsSeenByHosts + sep + avgSubsSeenPerHost + sep + avgHostsSeenPerSub;

				String userCLROutStr = new String();
				String vmCLROutStr = new String();
				String unsafeSubVMCLROutStr = new String();
				String safeVMTimeStr = new String();
				String unsafeSubSafeVMTimeStr = new String();
				String safeSubTimeStr = new String();
				String totalCoverageStr = new String();
				for(int ms = 0; ms < malsubProp.length; ms++) {
					userCLROutStr += sep + userCLR[ms];
					vmCLROutStr += sep + vmCLR[ms];
					unsafeSubVMCLROutStr += sep + unsafeSubVmCLR[ms];
					safeVMTimeStr += sep + safeVMTimeProportion[ms][0];
					unsafeSubSafeVMTimeStr += sep + safeVMTimeProportion[ms][1];
					safeSubTimeStr += sep + safeSubTimeProportion[ms];
					totalCoverageStr += sep + totalCoverage[ms];
				}

				outstr += userCLROutStr + vmCLROutStr + unsafeSubVMCLROutStr + safeVMTimeStr + unsafeSubSafeVMTimeStr + safeSubTimeStr + totalCoverageStr + "\n";

				String outputFilenamePrefix = cmd.getOptionValue(outputFileOpt.getOpt());
				String outputFilename = outputFilenamePrefix + ".csv";
				File outfile = new File(outputFilename);
				boolean addHeader = false;
				if(!outfile.exists()) {
					addHeader = true;
				}
				FileOutputStream os = new FileOutputStream(outfile, true);
				PrintWriter ow = new PrintWriter(os);

				if(addHeader) {
					String header = "algorithm" + sep + "seed" + sep + "maldata" + sep + "CU" + sep + "avgHosts" + sep + "maxHosts" + sep + "hostBoots" + sep + "hostShutdowns" + sep + "numVMCreations" + sep + "avgActiveVMs" + sep + "maxActiveVMs" + sep + "totalSubKnownEntries" + sep + "avgSubsKnownPerSub" + sep + "totalSubsSeenByHosts" + sep + "avgSubsSeenPerHost" + sep + "avgHostsSeenPerSub";

					String userCLRHeader = new String();
					String vmCLRHeader = new String();
					String unsafeSubVmCLRHeader = new String();
					String safeVMTimeHeader = new String();
					String unsafeSubSafeVMTimeHeader = new String();
					String safeSubTimeHeader = new String();
					String totalCoverageHeader = new String();

					for(int ms = 0; ms < malsubProp.length; ms++) {
						userCLRHeader += sep + "userCLR-ms" + malsubProp[ms];
						vmCLRHeader += sep + "vmCLR-ms" + malsubProp[ms];
						unsafeSubVmCLRHeader += sep + "unsafeSubVMCLR-ms" + malsubProp[ms];
						safeVMTimeHeader += sep + "safeVMTimeProp-ms" + malsubProp[ms];
						unsafeSubSafeVMTimeHeader += sep + "unsafeSubSafeVMTimeProp-ms" + malsubProp[ms];
						safeSubTimeHeader += sep + "safeSubTimeProp-ms" + malsubProp[ms];
						totalCoverageHeader += sep + "totalCoverage-ms" + malsubProp[ms];
					}

					header += userCLRHeader + vmCLRHeader + unsafeSubVmCLRHeader + safeVMTimeHeader + unsafeSubSafeVMTimeHeader + safeSubTimeHeader + totalCoverageHeader + "\n";
					ow.write(header);
				}

				ow.write(outstr);
				ow.close();
				os.close();

				File cuOutputFile = new File(outputFilenamePrefix + "-overallcu.csv");
				String cuStatString = alg.getCuStatString();
				writeStatStringToCSV(cuOutputFile, cuStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File intcuOutputFile = new File(outputFilenamePrefix + "-intcu.csv");
				String intcuStatString = alg.getIntCuStatString();
				writeStatStringToCSV(intcuOutputFile, intcuStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				for(int ms = 0; ms < malsubProp.length; ms++) {
					File userCLROutputFile = new File(outputFilenamePrefix + "-mal" + malsubProp[ms] + "-userclr.csv");
					String userCLRStatString = alg.getUserCLRString(ms);
					writeStatStringToCSV(userCLROutputFile, userCLRStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

					File vmCLROutputFile = new File(outputFilenamePrefix + "-mal" + malsubProp[ms] + "-vmclr.csv");
					String vmCLRStatString = alg.getVmCLRString(ms);
					writeStatStringToCSV(vmCLROutputFile, vmCLRStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

					File unsafeSubVMCLROutputFile = new File(outputFilenamePrefix + "-mal" + malsubProp[ms] + "-unsafesubvmclr.csv");
					String unsafeSubVMCLRStatString = alg.getUnsafeSubVMCLRString(ms);
					writeStatStringToCSV(unsafeSubVMCLROutputFile, unsafeSubVMCLRStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

					File newVMCLROutputFile = new File(outputFilenamePrefix + "-mal" + malsubProp[ms] + "-newvmclr.csv");
					String newVMCLRStatString = alg.getNewVMCLRStr(ms);
					writeStatStringToCSV(newVMCLROutputFile, newVMCLRStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

					File unsafeSubNewVMCLROutputFile = new File(outputFilenamePrefix + "-mal" + malsubProp[ms] + "-unsafesubnewvmclr.csv");
					String unsafeSubNewVMCLRStatString = alg.getUnsafeSubNewVMCLRString(ms);
					writeStatStringToCSV(unsafeSubNewVMCLROutputFile, unsafeSubNewVMCLRStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

					File coverageOutputFile = new File(outputFilenamePrefix + "-mal" + malsubProp[ms] + "-coverage.csv");
					String coverageString = alg.getCoverageString(ms);
					writeStatStringToCSV(coverageOutputFile, coverageString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);
				}

				File avgVMOutputFile = new File(outputFilenamePrefix + "-avgvms.csv");
				String avgVMStatString = alg.getAvgVMStr();
				writeStatStringToCSV(avgVMOutputFile, avgVMStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File maxVMOutputFile = new File(outputFilenamePrefix + "-maxvms.csv");
				String maxVMStatString = alg.getMaxVMStr();
				writeStatStringToCSV(maxVMOutputFile, maxVMStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File minVMOutputFile = new File(outputFilenamePrefix + "-minvms.csv");
				String minVMStatString = alg.getMinVMStr();
				writeStatStringToCSV(minVMOutputFile, minVMStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File maxHostsOutputFile = new File(outputFilenamePrefix + "-maxhosts.csv");
				String maxHostsStatString = alg.getMaxHostsStr();
				writeStatStringToCSV(maxHostsOutputFile, maxHostsStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File minHostsOutputFile = new File(outputFilenamePrefix + "-minhosts.csv");
				String minHostsStatString = alg.getMinHostsStr();
				writeStatStringToCSV(minHostsOutputFile, minHostsStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File avgHostsOutputFile = new File(outputFilenamePrefix + "-avghosts.csv");
				String avgHostsStatString = alg.getAvgHostsStr();
				writeStatStringToCSV(avgHostsOutputFile, avgHostsStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File vmCreationsOutputFile = new File(outputFilenamePrefix + "-vmcreations.csv");
				String vmCreationsStatString = alg.getVMCreationsStr();
				writeStatStringToCSV(vmCreationsOutputFile, vmCreationsStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File vmDeletionsOutputFile = new File(outputFilenamePrefix + "-vmdeletions.csv");
				String vmDeletionsStatString = alg.getVMDeletionsStr();
				writeStatStringToCSV(vmDeletionsOutputFile, vmDeletionsStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File hostsBootedOutputFile = new File(outputFilenamePrefix + "-hostboots.csv");
				String hostsBootedStatString = alg.getHostsBootedStr();
				writeStatStringToCSV(hostsBootedOutputFile, hostsBootedStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				File hostsShutDownOutputFile = new File(outputFilenamePrefix + "-hostshutdowns.csv");
				String hostsShutDownStatString = alg.getHostsShutDownStr();
				writeStatStringToCSV(hostsShutDownOutputFile, hostsShutDownStatString, seed, malsubdataStr, minTime, maxTime, statInterval, statMinTime, sep);

				// Generate statistics for This is currently incompatible with multiple malSets.
				if(cmd.hasOption(maliciousSubDataOpt.getOpt())) {
					File targetOutputFile = new File(outputFilenamePrefix + "-target.csv");
					boolean addTargetOutputFileHeader = false;
					if(!targetOutputFile.exists()) {
						addTargetOutputFileHeader = true;
					}
					FileOutputStream targetOs = new FileOutputStream(targetOutputFile, true);
					PrintWriter targetOw = new PrintWriter(targetOs);

					File hitEventOutputFile = new File(outputFilenamePrefix + "-" + malsubdataStr  + "-hits.csv");
					boolean addHitEventOutputFileHeader = false;
					if(!hitEventOutputFile.exists()) {
						addHitEventOutputFileHeader = true;
					}
					FileOutputStream hitEventOs = new FileOutputStream(hitEventOutputFile, true);
					PrintWriter hitEventOw = new PrintWriter(hitEventOs);

					File malEventOutputFile = new File(outputFilenamePrefix +  "-" + malsubdataStr + "-malevents.csv");
					boolean addMalEventOutputFileHeader = false;
					if(!malEventOutputFile.exists()) {
						addMalEventOutputFileHeader = true;
					}
					FileOutputStream malEventOs = new FileOutputStream(malEventOutputFile, true);
					PrintWriter malEventOw = new PrintWriter(malEventOs);

					if(addTargetOutputFileHeader) {
						// Stats for benign VMs and benign subscriptions are unnecessary: CLRs give the same information.
						String targetHeader = //"totalBenignVMs" + sep + "benignVMsSeen" + sep + "benignVMsSeenProp" + sep
								//+  "totalBenignSubs" + sep + "benignSubsSeen" + sep + "benignSubsSeenProp" + sep +
								"malsubdata" + sep + "totalHosts" + sep + "hostsSeen" + sep + "hostsSeenProp" + sep
										+ "totalTargetVMs" + sep + "targetVMsSeen" + sep + "targetVMsSeenProp" + sep
										+ "totalTargetSubs" + sep + "targetSubsSeen" + sep + "targetSubsSeenProp" + "\n";
						targetOw.write(targetHeader);
					}

					if(addHitEventOutputFileHeader) {
						String hitEventHeader = "time" + sep + "vm" + sep + "subscription" + sep + "host" + sep
								+ "targetVM" + sep + "targetSub" + "\n";
						hitEventOw.write(hitEventHeader);
					}

					if (!noMalevents && addMalEventOutputFileHeader) {
						String malEventHeader = "time" + sep + "hit?" + sep + "vm" + sep + "subscription" + sep + "host"
								+ sep + "targetVM" + sep + "targetSub" + "\n";
						malEventOw.write(malEventHeader);
					}

					int totalHosts = hosts.length;
					int coveredHosts = 0;
					for(Host h : hosts) {
						if(h.hasHostedMaliciousSubscription(0)) {
							coveredHosts++;
						}
					}
					double coveredHostsProp = (double)coveredHosts/totalHosts;

					HashSet<VM> targetVMs = new HashSet<VM>();
					HashSet<VM> targetVMsHit = new HashSet<VM>();
					HashSet<Subscription> targetSubs = new HashSet<Subscription>();
					HashSet<Subscription> targetSubsHit = new HashSet<Subscription>();
					for(VM malVM : malSubDataVMs) {
						int time = malVM.getTimeCreated();
						String malID = malVM.getID();
						String malSubID = malVM.getSubscription().getID();
						int hostID = malVM.getHost().getHostNumber();
						if(malVM.hasTarget()) {
							VM targetVM = malVM.getTargetVM();
							targetVMs.add(targetVM);
							targetSubs.add(targetVM.getSubscription());

							String targetVmId = targetVM.getID();
							String targetSubId = targetVM.getSubscription().getID();

							if(malVM.hasHitTarget()) {
								targetVMsHit.add(targetVM);
								targetSubsHit.add(targetVM.getSubscription());

								hitEventOw.write(time + sep + malID + sep + malSubID + sep + hostID + sep
										+ targetVmId + sep + targetSubId + "\n");
							}

							if(!noMalevents) {
								malEventOw.write(time + sep + malVM.hasHitTarget() + sep + malID + sep + malSubID + sep
										+ hostID + sep + targetVmId + sep + targetSubId + "\n");
							}
						} else {
							if(!noMalevents) {
								malEventOw.write(time + sep + "n/a" + sep + malID + sep + malSubID + sep
										+ hostID + sep + sep + "\n");
							}
						}
					}

					int numTargetVMs = targetVMs.size();
					int numTargetVMsHit = targetVMsHit.size();
					double targetVMsHitProp = (double)numTargetVMsHit / numTargetVMs;

					int numTargetSubs = targetSubs.size();
					int numTargetSubsHit = targetSubsHit.size();
					double targetSubsHitProp = (double)numTargetSubsHit / numTargetSubs;

					targetOw.write(malsubdataStr + sep + totalHosts + sep + coveredHosts + sep + coveredHostsProp + sep + numTargetVMs
							+ sep + numTargetVMsHit + sep + targetVMsHitProp + sep + numTargetSubs + sep
							+ numTargetSubsHit + sep + targetSubsHitProp + "\n");

					targetOw.close();
					targetOs.close();
					hitEventOw.close();
					hitEventOs.close();
					malEventOw.close();
					malEventOs.close();
				}
			}
		} catch (MissingOptionException e) {
			printHelp(opt);
			System.exit(1);
		} catch (ParseException e) {
			System.err.println("Error: Could not parse CLI options.");
			e.printStackTrace();
			System.exit(1);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Helper method for writing statistics to an output CSV file.
	 *
	 * @param outfile output File
	 * @param string statistics String to write to outfile
	 * @param seed seed used to initialise PRNG for simulation
	 * @param maldataStr identifier for malicious user data used in simulation
	 * @param startTime start time of simulation
	 * @param endTime end time of simulation
	 * @param statInterval statistics interval
	 * @param statMinTime first time for which statistics are generated
	 * @param sep field separator
	 * @throws IOException
	 */
	private static void writeStatStringToCSV(File outfile, String string, long seed, String maldataStr, int startTime, int endTime, int statInterval, int statMinTime, String sep) throws IOException {
		boolean addHeader = false;
		if(!outfile.exists()) {
			addHeader = true;
		}
		FileOutputStream os = new FileOutputStream(outfile, true);
		PrintWriter ow = new PrintWriter(os);

		if(addHeader) {
			String headerStr = "seed" + sep + "maldata";
			int t = statMinTime + statInterval;
			while(t < endTime) {
				headerStr += sep + t;
				t += statInterval;
			}
			headerStr += sep + endTime;
			ow.write(headerStr + "\n");
		}

		ow.write(seed + sep + maldataStr + sep + string + "\n");
		ow.close();
		os.close();
	}

	/**
	 * Prints the help message containing information about the CLI options.
	 * @param opt Options object containing CLI options.
	 */
	private static void printHelp(Options opt) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("MemSigs", opt);
	}

	/**
	 * Sorts the VMs by their creation time.
	 * @param vms Collection of VMs
	 * @return sorted array of VMs
	 */
	private static VM[] sortVMsByCreation(Collection<VM> vms) {
		List<VM> sorted = vms.stream().sorted(Comparator.comparingInt(VM::getTimeCreated)).collect(Collectors.toList());
		return sorted.toArray(new VM[0]);
	}

	/**
	 * Sorts the VMs by their deletion time.
	 * @param vms Collection of VMs
	 * @return sorted array of VMs
	 */
	private static VM[] sortVMsByDeletion(Collection<VM> vms) {
		List<VM> sorted = vms.stream().sorted(Comparator.comparingInt(VM::getTimeDeleted)).collect(Collectors.toList());
		return sorted.toArray(new VM[0]);
	}

	/**
	 * Marks a proportion of Subscriptions as malicious.
	 * @param subs array of Subscriptions to work on
	 * @param malicious proportion of Subscriptions to mark as malicious
	 * @param seed seed value for initialisation of PRNG
	 */
	public static void makeSubscriptionsMalicious(Subscription[] subs, double[] malicious, long seed) {
		int numSubs = subs.length;

		for(int i = 0; i < malicious.length; i++) {
			Random rnd = new Random(seed);
			int numMalicious = (int)Math.round((double)numSubs*malicious[i]);

			while(numMalicious > 0) {
				int r = rnd.nextInt(numSubs);

				if(!subs[r].isMalicious(i)) {
					subs[r].setMalicious(i, true);
					numMalicious--;
				} // else try again...
			}
		}
	}
}