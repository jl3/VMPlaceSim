// SPDX-FileCopyrightText: 2023 Jens Lindemann
// SPDX-License-Identifier: BSD-3-Clause

package de.unihamburg.vmplacesim.helper;

import java.util.Random;

/**
 *
 * @author Jens Lindemann
 */

public class SeedGenerator {
    public static void main(String[] args) {
        Random r = new Random();
        for(int i = 0; i < 100; i++) {
            System.out.println(r.nextLong());
        }
    }
}
