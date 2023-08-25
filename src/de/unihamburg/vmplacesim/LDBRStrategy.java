// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim;

import org.apache.commons.math3.distribution.BetaDistribution;
import org.apache.commons.math3.random.Well19937c;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Random;

/**
 * Implements the LDBR strategy proposed by Xiao et al.
 *
 * This implementation includes a simulation for the calculation of probability values for individual subscriptions,
 * as Xiao et al. unfortunately do not describe how to generate these.
 *
 * This can only be used with *one* specific malicious set, as Host selection depends on whether a Subscription is
 * malicious.
 *
 * @author Jens Lindemann
 */
public class LDBRStrategy extends PlacementStrategy {
    private boolean _subscriptionBased;
    private double _maliciousProportion;

    private Hashtable<Subscription, Double> _pValues;
    private BetaDistribution _maliciousDist;
    private BetaDistribution _benignDist;


    public LDBRStrategy(int numberOfHosts, int activeHosts, int coresPerHost, double memoryPerHost, Random random, int startTime, int statInterval, int statMinTime, int maliciousSets, double maliciousProportion, double pertMode, double pertLamba, long seed) {
        super(numberOfHosts, activeHosts, coresPerHost, memoryPerHost, random, startTime, statInterval, statMinTime, maliciousSets, false, false);

        if(maliciousSets != 1) {
            System.err.println("Error: LDBRStrategy must be used with exactly one malicous set!");
            System.exit(-1);
        }

        if(pertMode < 0.0 || pertMode > 1.0) {
            System.err.println("Error: Detection accuracy must be between 0.5 and 1.0.");
            System.exit(-1);
        }

        _maliciousProportion = maliciousProportion;
        _pValues = new Hashtable<Subscription, Double>();

        double[] maliciousShape = generatePERTShapeParams(0, 1, pertMode, pertLamba);
        double[] benignShape = generatePERTShapeParams(0, 1, 1-pertMode, pertLamba);
        Well19937c distrnd = new Well19937c(seed+2);
        _maliciousDist = new BetaDistribution(distrnd, maliciousShape[0], maliciousShape[1]);
        _benignDist = new BetaDistribution(distrnd, benignShape[0], benignShape[1]);
    }

    @Override
    /**
     * Picks a Host for a VM.
     *
     * This *may return null if there is no Host with sufficient capacity.
     */
    protected Host pickHost(VM vm) {
        Subscription sub = vm.getSubscription();
        ArrayList<Host> eligibleHosts = new ArrayList<Host>();
        double minE = Double.MAX_VALUE;

        Double newP = _pValues.get(sub);
        if(newP == null) {
            // set and put p value
            if(sub.isMalicious(0)) {
                newP = generateMaliciousPValue();
            } else {
                newP = generateBenignPValue();
            }
            _pValues.put(sub, newP);
        }

        for(Host h : _activeHosts) {
            if((h.freeCores() >= vm.getCores()) && (h.freeMemory() >= vm.getMemory())) {
                int numVMs = h.numberOfCurrentVMs();

                double pProduct = 1;
                for(VM hostvm : h.getCurrentVMs()) {
                    Subscription hostvmsub = hostvm.getSubscription();
                    double subp = _pValues.get(hostvmsub);
                    // no need to check whether this is null -- all of these have been processed before...
                    pProduct *= subp;
                }



                double eValue = numVMs*pProduct*(1-newP)+(1-pProduct)*newP;
                // Skipping the next step here, as ``Here we only consider security, so theta is always 1 and
                // epsilon is 0''.
                // eValue = eValue * theta + epsilon

                if(eValue < minE) {
                    minE = eValue;
                    eligibleHosts = new ArrayList<Host>();
                    eligibleHosts.add(h);
                } else if(eValue == minE) {
                    eligibleHosts.add(h);
                } // else ignore
            }
        }

        if(eligibleHosts.isEmpty()) {
            return pickEmptyHost(vm);
        } else {
            return pickRandomHost(eligibleHosts);
        }
    }

    // Implementation based on https://www.riskamp.com/beta-pert (accessed July 22, 2021)
    private static double[] generatePERTShapeParams(double min, double max, double mode, double lambda) {
        double mu = (min + max + lambda * mode) / (lambda + 2);

        double alpha;
        if(mu == mode) {
            alpha = (lambda / 2) + 1;
        } else {
            alpha = ((mu - min) * (2 * mode - min - max)) / ((mode - mu) * (max - min));
        }

        double beta = (alpha * (max - mu)) / (mu - min);

        double[] ret = {alpha, beta};
        return ret;
    }

    // Implementation based on https://www.riskamp.com/beta-pert (accessed July 22, 2021)
    private double generateMaliciousPValue() {
        // range = 1.0, min = 0.0
        return _maliciousDist.sample() * 1 + 0;
    }

    // Implementation based on https://www.riskamp.com/beta-pert (accessed July 22, 2021)
    private double generateBenignPValue() {
        // range = 1.0, min = 0.0
        return _benignDist.sample() * 1 + 0;
    }
}
