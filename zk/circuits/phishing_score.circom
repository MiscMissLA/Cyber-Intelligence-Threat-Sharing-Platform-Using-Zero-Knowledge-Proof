pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

template ScoreAboveThreshold(threshold) {
    signal input score;
    signal output passed;

    component isBelow = LessThan(8); // 8 bits covers scores 0–255
    isBelow.in[0] <== score;
    isBelow.in[1] <== threshold;

    // passed is 1 if score > threshold, so passed = NOT isBelow.out
    passed <== 1 - isBelow.out;
}

component main = ScoreAboveThreshold(75);

