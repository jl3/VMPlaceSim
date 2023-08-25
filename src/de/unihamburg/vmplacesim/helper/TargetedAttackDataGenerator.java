// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim.helper;

import org.apache.commons.cli.*;
import de.unihamburg.vmplacesim.FileParser;
import de.unihamburg.vmplacesim.VM;

import java.io.*;
import java.util.ArrayList;
import java.util.Random;

/**
 * This class can be used to generate cloud workload representing targeted attackers, as described in the paper
 * accompanying the framrwork.
 *
 * @author Jens Lindemann
 */
public class TargetedAttackDataGenerator {
    private final String sep = ",";

    public TargetedAttackDataGenerator(int interval, int lifetime, int minTime, int maxTime, int cores, int memory, String subscriptionID, boolean newSubIdPerInterval, File outfile, File datasetfile, int datasetMinTime, int datasetMaxTime, Random rnd, int numBursts, int vmsPerBurst, int burstInterval, int burstTimeBeforeTargetCreation) {
        try {
            VM[] vmCreations = readVMsFromDataset(datasetfile, datasetMinTime, datasetMaxTime);

            FileOutputStream fos = new FileOutputStream(outfile);
            PrintWriter out = new PrintWriter(fos);

            int vmidx = 0;
            timeloop:
            for(int time = minTime; time < maxTime && vmidx < vmCreations.length; time+=interval) {
                String intSubId = subscriptionID;
                if(newSubIdPerInterval) {
                    intSubId += "-" + time;
                }

                // Move to first VM created at or after time
                while(vmCreations[vmidx].getTimeCreated() < time) {
                    vmidx++;

                    if(vmidx >= vmCreations.length) {
                        break timeloop;
                    }
                }

                // Choose one of the VMs created at this time.
                int vmtime = vmCreations[vmidx].getTimeCreated();
                ArrayList<VM> timeVMs = new ArrayList<VM>();
                while(vmCreations[vmidx].getTimeCreated() == vmtime) {
                    timeVMs.add(vmCreations[vmidx]);
                    vmidx++;

                    if(vmidx >= vmCreations.length) {
                        break;
                    }
                }
                int rndidx = rnd.nextInt(timeVMs.size());
                VM targetVM = timeVMs.get(rndidx);

                String[] entries = generateEntries(intSubId, targetVM, cores, memory, numBursts, vmsPerBurst, lifetime, burstInterval, burstTimeBeforeTargetCreation);
                for(String entry : entries) {
                    out.write(entry + "\n");
                }

                // Make sure that time to next interval is not too short.
                while(vmtime >= time+interval) {
                    time += interval;
                }
            }

            out.close();
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String[] generateEntries(String subid, VM targetVM, int cores, int memory, int numBursts, int vmsPerBurst, int lifetime, int burstInterval, int timeBeforeTargetCreation) {
        String[] entries = new String[numBursts*vmsPerBurst];
        int creation = targetVM.getTimeCreated();

        int time = creation-timeBeforeTargetCreation;
        for(int b = 0; b < numBursts; b++) {
            for(int v = 0; v < vmsPerBurst; v++) {
                String vmid = subid + "-" + time + "-" + v;
                entries[b*vmsPerBurst+v] = generateEntry(vmid, subid, time, time+lifetime, cores, memory, targetVM.getID());
            }

            time+=burstInterval;
        }

        return entries;
    }

    private String generateEntry(String vmid, String subid, int creation, int deletion, int cores, int memory, String targetVMID) {
        Random rnd = new Random();
        String str = vmid
                + sep + subid
                + sep +  rnd.nextInt() // deployment id, is ignored in simulation anyway
                + sep + creation
                + sep + deletion
                + sep + 0 // maxCPU -- ignored in simulation
                + sep + 0 // avgCPU -- ignored in simulation
                + sep + 0 // p95CPU -- ignored in simulation
                + sep + "Unknown" // vm category -- ignored in simulation
                + sep + cores
                + sep + memory
                + sep + targetVMID;
        return str;
    }

    private VM[] readVMsFromDataset(File file, int minTime, int maxTime) {
        System.out.println("Parsing input files...");
        FileParser fparser = new FileParser(file, minTime, maxTime, 1);
        return fparser.getVMsSortedByCreation();
    }

    /**
     * Prints the help message containing information about the CLI options.
     * @param opt Options object containing CLI options.
     */
    private static void printHelp(Options opt) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("MemSigs", opt);
    }

    public static void main(String[] args) {
        Options opt = new Options();

        // define CLI options
        Option intervalOpt = Option.builder("i")
                .required()
                .longOpt("interval")
                .hasArg()
                .argName("time")
                .desc("defines the interval between attack bursts")
                .build();

        Option lifetimeOpt = Option.builder("l")
                .required()
                .longOpt("lifetime")
                .hasArg()
                .argName("time")
                .desc("lifetime of VMs")
                .build();

        Option outputFilenameOpt = Option.builder("f")
                .required()
                .longOpt("outputfile")
                .hasArg()
                .argName("file")
                .desc("output filename")
                .build();

        Option minTimeOpt = Option.builder("min")
                .required()
                .longOpt("mintime")
                .hasArg()
                .argName("time")
                .desc("minimum time")
                .build();

        Option maxTimeOpt = Option.builder("max")
                .required()
                .longOpt("maxtime")
                .hasArg()
                .argName("time")
                .desc("maximum time")
                .build();

        Option subscriptionIDOpt = Option.builder("subid")
                .required()
                .longOpt("subscriptionid")
                .hasArg()
                .argName("id")
                .desc("subscription ID")
                .build();

        Option newSubIdOpt = Option.builder("ns")
                .longOpt("newsubidperinterval")
                .desc("Change the subscription ID per interval. If set, the ID specified is used as a prefix for the changing IDs.")
                .build();

        Option coresOpt = Option.builder("c")
                .longOpt("cores")
                .hasArg()
                .argName("cores")
                .desc("number of cores per VM (default: 2)")
                .build();

        Option memoryOpt = Option.builder("m")
                .longOpt("memory")
                .hasArg()
                .argName("GiB")
                .desc("memory allocation per VM (default: 4 GiB)")
                .build();

        Option datasetOpt = Option.builder("d")
                .required()
                .longOpt("dataset")
                .hasArg()
                .argName("file")
                .desc("dataset for which attack data should be generated")
                .build();

        Option datasetMinTimeOpt = Option.builder("dmin")
                .longOpt("datasetmintime")
                .hasArg()
                .argName("time")
                .desc("minimum time for loading dataset (must be <=min, default: min)")
                .build();

        Option datasetMaxTimeOpt = Option.builder("dmax")
                .longOpt("datasetmintime")
                .hasArg()
                .argName("time")
                .desc("maximum time for loading dataset (must be >=max, default: max)")
                .build();

        Option rndSeedOpt = Option.builder("s")
                .longOpt("seed")
                .hasArg()
                .argName("seed")
                .desc("sets the seed")
                .build();

        Option burstsOpt = Option.builder("bursts")
                .required()
                .hasArg()
                .argName("number")
                .desc("Sets the number of VM creation bursts per target VM.")
                .build();

        Option vmsPerBurstOpt = Option.builder("burstvms")
                .required()
                .hasArg()
                .argName("vms")
                .desc("Sets the number of VMs per creation burst.")
                .build();

        Option burstIntervalOpt = Option.builder("burstint")
                .required()
                .hasArg()
                .argName("interval")
                .desc("Sets the interval between VM creation burst.")
                .build();

        Option burstTimeBeforeTargetCreationOpt = Option.builder("burstbeforetarget")
                .hasArg()
                .argName("time")
                .desc("Sets the time of the first burst before the target VM creation (default: 0).")
                .build();

        Option helpOpt = Option.builder("h")
                .longOpt("help")
                .desc("print this message")
                .build();

        opt.addOption(intervalOpt);
        //opt.addOption(vmsPerIntervalOpt);
        opt.addOption(lifetimeOpt);
        opt.addOption(outputFilenameOpt);
        opt.addOption(minTimeOpt);
        opt.addOption(maxTimeOpt);
        opt.addOption(subscriptionIDOpt);
        opt.addOption(newSubIdOpt);
        opt.addOption(datasetOpt);
        opt.addOption(datasetMinTimeOpt);
        opt.addOption(datasetMaxTimeOpt);
        opt.addOption(rndSeedOpt);
        opt.addOption(burstsOpt);
        opt.addOption(vmsPerBurstOpt);
        opt.addOption(burstIntervalOpt);
        opt.addOption(burstTimeBeforeTargetCreationOpt);
        opt.addOption(helpOpt);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(opt, args);

            if(cmd.hasOption(helpOpt.getOpt())) {
                printHelp(opt);
            }

            int interval = Integer.parseInt(cmd.getOptionValue(intervalOpt.getOpt()));
            int lifetime = Integer.parseInt(cmd.getOptionValue(lifetimeOpt.getOpt()));
            int minTime = Integer.parseInt(cmd.getOptionValue(minTimeOpt.getOpt()));
            int maxTime = Integer.parseInt(cmd.getOptionValue(maxTimeOpt.getOpt()));
            String subscriptionID = cmd.getOptionValue(subscriptionIDOpt.getOpt());
            String outfilename = cmd.getOptionValue(outputFilenameOpt.getOpt());
            String datasetFilename = cmd.getOptionValue(datasetOpt.getOpt());
            int numBursts = Integer.parseInt(cmd.getOptionValue(burstsOpt.getOpt()));
            int vmsPerBurst = Integer.parseInt(cmd.getOptionValue(vmsPerBurstOpt.getOpt()));
            int burstInterval = Integer.parseInt(cmd.getOptionValue(burstIntervalOpt.getOpt()));

            int burstTimeBeforeTargetCreation = 0;
            if (cmd.hasOption(burstTimeBeforeTargetCreationOpt.getOpt())) {
                burstTimeBeforeTargetCreation = Integer.parseInt(cmd.getOptionValue(burstTimeBeforeTargetCreationOpt.getOpt()));
            }

            int datasetMinTime = minTime;
            if(cmd.hasOption(datasetMinTimeOpt.getOpt())) {
                datasetMinTime = Integer.parseInt(cmd.getOptionValue(datasetMinTimeOpt.getOpt()));
            }

            int datasetMaxTime = maxTime;
            if(cmd.hasOption(datasetMaxTimeOpt.getOpt())) {
                datasetMaxTime = Integer.parseInt(cmd.getOptionValue(datasetMaxTimeOpt.getOpt()));
            }

            int cores = 2;
            if(cmd.hasOption(coresOpt.getOpt())) {
                cores = Integer.parseInt(cmd.getOptionValue(coresOpt.getOpt()));
            }

            int memory = 4;
            if(cmd.hasOption(memoryOpt.getOpt())) {
                memory = Integer.parseInt(cmd.getOptionValue(memoryOpt.getOpt()));
            }

            boolean newSubIdPerInterval = false;
            if(cmd.hasOption(newSubIdOpt.getOpt())) {
                newSubIdPerInterval = true;
            }

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

            File outfile = new File(outfilename);
            File datasetfile = new File(datasetFilename);
            TargetedAttackDataGenerator iadg = new TargetedAttackDataGenerator(interval, lifetime, minTime, maxTime, cores, memory, subscriptionID, newSubIdPerInterval, outfile, datasetfile, datasetMinTime, datasetMaxTime, rnd, numBursts, vmsPerBurst, burstInterval, burstTimeBeforeTargetCreation);
        } catch (MissingOptionException e) {
            printHelp(opt);
            System.exit(1);
        } catch (ParseException e) {
            System.err.println("Error: Could not parse CLI options.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
