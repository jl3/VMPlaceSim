// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim.helper;

import org.apache.commons.cli.*;

import java.io.*;
import java.util.Random;

/**
 * This class can be used to generate cloud workload representing isochronous attackers, as described in the paper
 * accompanying the framrwork.
 *
 * @author Jens Lindemann
 */
public class IntervalAttackDataGenerator {
    private final String sep = ",";

    public IntervalAttackDataGenerator(int interval, int vmsPerInterval, int lifetime, int minTime, int maxTime, int cores, int memory, String subscriptionID, boolean newSubIdPerInterval, File outfile) {
        try {
            FileOutputStream fos = new FileOutputStream(outfile);
            PrintWriter out = new PrintWriter(fos);

            int i = 0;
            for(int time = minTime; time < maxTime; time+=interval) {
                String intSubId = subscriptionID;
                if(newSubIdPerInterval) {
                    intSubId += "-" + time;
                }

                for(int j = 0; j < vmsPerInterval; j++) {
                    String vmID = intSubId + "-" + i;
                    String entryStr = generateEntry(vmID, intSubId, time, time + lifetime, cores, memory);
                    out.write(entryStr + "\n");
                    i++;
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

    private String generateEntry(String vmid, String subid, int creation, int deletion, int cores, int memory) {
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
                + sep + memory;
        return str;
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

        Option vmsPerIntervalOpt = Option.builder("v")
                .required()
                .longOpt("vmsperinterval")
                .hasArg()
                .argName("number of VMs")
                .desc("defines the number of VMs launched per interval")
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

        Option helpOpt = Option.builder("h")
                .longOpt("help")
                .desc("print this message")
                .build();

        opt.addOption(intervalOpt);
        opt.addOption(vmsPerIntervalOpt);
        opt.addOption(lifetimeOpt);
        opt.addOption(outputFilenameOpt);
        opt.addOption(minTimeOpt);
        opt.addOption(maxTimeOpt);
        opt.addOption(subscriptionIDOpt);
        opt.addOption(newSubIdOpt);
        opt.addOption(helpOpt);

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(opt, args);

            if(cmd.hasOption(helpOpt.getOpt())) {
                printHelp(opt);
            }

            int interval = Integer.parseInt(cmd.getOptionValue(intervalOpt.getOpt()));
            int vmsPerInterval = Integer.parseInt(cmd.getOptionValue(vmsPerIntervalOpt.getOpt()));
            int lifetime = Integer.parseInt(cmd.getOptionValue(lifetimeOpt.getOpt()));
            int minTime = Integer.parseInt(cmd.getOptionValue(minTimeOpt.getOpt()));
            int maxTime = Integer.parseInt(cmd.getOptionValue(maxTimeOpt.getOpt()));
            String subscriptionID = cmd.getOptionValue(subscriptionIDOpt.getOpt());
            String outfilename = cmd.getOptionValue(outputFilenameOpt.getOpt());

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

            File outfile = new File(outfilename);
            IntervalAttackDataGenerator iadg = new IntervalAttackDataGenerator(interval, vmsPerInterval, lifetime, minTime, maxTime, cores, memory, subscriptionID, newSubIdPerInterval, outfile);
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
