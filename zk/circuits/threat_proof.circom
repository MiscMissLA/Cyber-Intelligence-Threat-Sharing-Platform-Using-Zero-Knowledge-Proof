pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

template ThreatProof() {
    signal input score;
    signal input threshold;
    signal output isThreat;

    signal lt;

    component lessThan = LessThan(32);
    lessThan.in[0] <== threshold;
    lessThan.in[1] <== score;
    lt <== lessThan.out;

    isThreat <== lt;
}

component main = ThreatProof();

