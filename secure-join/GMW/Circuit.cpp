#include "Circuit.h"
#include <string>
namespace secJoin
{

    BetaCircuit isZeroCircuit(u64 bits)
    {
        BetaCircuit cd;

        BetaBundle a(bits);

        cd.addInputBundle(a);

        //for (u64 i = 1; i < bits; ++i)
        //    cd.addGate(a.mWires[i], a.mWires[i], oc::GateType::Nxor, a.mWires[i]);
        auto ts = [](int s) {return std::to_string(s); };
        u64 step = 1;

        for (u64 i = 0; i < bits; ++i)
            cd.addInvert(a[i]);

        while (step < bits)
        {
            //std::cout << "\n step " << step << std::endl;
            cd.addPrint("\n step " + ts(step) + "\n");
            for (u64 i = 0; i + step < bits; i += step * 2)
            {
                cd.addPrint("a[" + ts(i) + "] & a[" + ts(i + step) + "] -> a[" + ts(i) + "]\n");
                cd.addPrint(a.mWires[i]);
                cd.addPrint(" & ");
                cd.addPrint(a.mWires[i + step]);
                cd.addPrint(" -> ");
                cd.addPrint(a.mWires[i]);
                //cd.addPrint("a[" + ts(i)+ "] &= a[" +ts(i + step) + "]\n");

                //std::cout << "a[" << i << "] &= a[" << (i + step) << "]" << std::endl;
                cd.addGate(a.mWires[i], a.mWires[i + step], oc::GateType::And, a.mWires[i]);
            }

            step *= 2;
        }
        //cd.addOutputBundle()
        a.mWires.resize(1);
        cd.mOutputs.push_back(a);

        cd.levelByAndDepth();

        return cd;
    }

    void isZeroCircuit_Test()
    {
        u64 n = 128, tt = 100;
        auto cir = isZeroCircuit(n);

        {
            oc::BitVector bv(n), out(1);
            cir.evaluate({ &bv, 1 }, { &out,1 }, false);

            if (out[0] != 1)
                throw RTE_LOC;
        }

        PRNG prng(oc::ZeroBlock);

        for (u64 i = 0; i < tt; ++i)
        {
            oc::BitVector bv(n), out(1);
            bv.randomize(prng);
            if (bv.hammingWeight() == 0)
                continue;

            cir.evaluate({ &bv, 1 }, { &out,1 }, false);

            if (out[0] != 0)
                throw RTE_LOC;
        }


    }

    // add the evaluation of `cir` to the `parent` circuit where
    // `inputs` are the input wires to the circuit and 
    // `outputs` are the output wires.
    void evaluate(oc::BetaCircuit& parent, const oc::BetaCircuit& cir, span<BetaBundle> inputs, span<BetaBundle> outputs)
    {
        if (cir.mInputs.size() != inputs.size())
            throw std::runtime_error(LOCATION);
        if (cir.mOutputs.size() != outputs.size())
            throw std::runtime_error(LOCATION);

        // count the number of internal wires in the circuit.
        u64 tempCount = cir.mWireCount;
        for (u64 i = 0; i < inputs.size(); i++)
        {
            if (cir.mInputs[i].size() != inputs[i].size())
                throw std::runtime_error(LOCATION);

            tempCount -= inputs[i].size();
        }

        for (u64 i = 0; i < outputs.size(); i++)
        {
            if (cir.mOutputs[i].size() != outputs[i].size())
                throw std::runtime_error(LOCATION);

            tempCount -= outputs[i].size();
        }

        // allocate the internal wires
        oc::BetaBundle temp(tempCount);
        parent.addTempWireBundle(temp);

        // flatten all the wires for cir into an array.
        oc::BetaBundle wires(cir.mWireCount);
        for (u64 i = 0; i < inputs.size(); i++)
        {
            for (u64 j = 0; j < inputs[i].size(); j++)
                wires[cir.mInputs[i][j]] = inputs[i][j];
        }
        for (u64 i = 0; i < outputs.size(); i++)
            for (u64 j = 0; j < outputs[i].size(); j++)
                wires[cir.mOutputs[i][j]] = outputs[i][j];
        for (u64 i = 0; i < temp.size(); i++)
            wires[i + cir.mWireCount - tempCount] = temp[i];

        // evaluate the circuit.
        for (u64 i = 0; i < cir.mGates.size(); i++)
        {
            auto& gate = cir.mGates[i];
            auto& in0 = wires[gate.mInput[0]];
            auto& in1 = wires[gate.mInput[1]];
            auto& out = wires[gate.mOutput];
            if (gate.mType == oc::GateType::a)
                parent.addCopy(in0, out);
            else
                parent.addGate(in0, in1, gate.mType, out);
        }
    }

}
