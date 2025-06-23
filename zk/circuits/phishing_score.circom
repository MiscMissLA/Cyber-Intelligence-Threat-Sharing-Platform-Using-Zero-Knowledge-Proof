pragma circom 2.0.0;

include "circomlib2/comparators.circom";
template ScoreAboveThreshold(threshold) {
    signal input score;
    signal output passed;
    component isBelow = LessThan(8);
    isBelow.in[0] <== score;
    isBelow.in[1] <== threshold;
    passed <== 1 - isBelow.out;
}

component main = ScoreAboveThreshold(75);

