// Copyright (c) 2016-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <key.h>
#if defined(HAVE_CONSENSUS_LIB)
#include <script/bitcoinconsensus.h>
#endif
#include <script/script.h>
#include <script/sign.h>
#include <array>
#include <vector>
#include <rpc/blockchain.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <coins.h>
#include <consensus/validation.h>
#include <validation.h>
#include <core_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <util.h>
#include <utilstrencodings.h>
#include <hash.h>
#include <validationinterface.h>
#include <warnings.h>
#include "config.h"

#include <stdint.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

#include <mutex>
#include <condition_variable>

extern unsigned long time_of_secp256k1_ecdsa_sig_verify;
extern unsigned long count_of_secp256k1_ecdsa_sig_verify;
extern unsigned long time_of_CSHA256_Write;
extern unsigned long count_of_CSHA256_Write;
extern unsigned long data_len_of_CSHA256_Write;
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks);
// FIXME: Dedup with BuildCreditingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildCreditingTransaction(const CScript& scriptPubKey)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = Amount(1);

    return txCredit;
}

// FIXME: Dedup with BuildSpendingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildSpendingTransaction(const CScript& scriptSig, const CMutableTransaction& txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

#if 1
static bool checkScriptForBlock(const int nHeight)
{
    CBlock block;
    const Config &config = GetConfig();
    if (nHeight < 0 || nHeight > chainActive.Height())
    {
//        return error("%s: Block height out of range", __func__);
    }
    CBlockIndex* pblockindex = chainActive[nHeight];
    //return pblockindex->GetBlockHash();
    if (!ReadBlockFromDisk(block, pblockindex, config))
        return error("%s: Block not found in disk", __func__);

    std::cout << "The size of Block is " << block.vtx.size();
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
 //       unsigned int flags = GetBlockScriptFlags(pblockindex, Params().GetConsensus());
          unsigned int flags = 0;
        std::vector<PrecomputedTransactionData> txdata;
        txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
        txdata.emplace_back(tx);
#if 0
        if (!tx.IsCoinBase())
        {
            CValidationState stateDummy; // Want reported failures to be from first CheckInputs
            if (!CheckInputs(tx, stateDummy, pcoinsTip.get(), true, flags, false, false, txdata[i], nullptr))
                return error("CheckInputs on %s failed",
                    tx.GetHash().ToString());
        }
#endif
    }
}
#endif

// Microbenchmark for verification of a basic P2WPKH script. Can be easily
// modified to measure performance of other types of scripts.
static void MyVerifyScriptBench(benchmark::State& state)
{
    checkScriptForBlock(180000);
}


static void MyVerifyScriptBench_old(benchmark::State& state)
{
    const int flags = 0; //SCRIPT_VERIFY_P2SH;

    // Keypair.
    CKey key;
    std::vector<unsigned char> sig1;
    static const std::array<unsigned char, 32> vchKey = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        }
    };
    key.Set(vchKey.begin(), vchKey.end(), false);
    CPubKey pubkey = key.GetPubKey();
    uint160 pubkeyHash;
    CHash160().Write(pubkey.begin(), pubkey.size()).Finalize(pubkeyHash.begin());

    // Script.
    CScript scriptSig;
    CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;
    CMutableTransaction txCredit = BuildCreditingTransaction(scriptPubKey);
    CMutableTransaction txSpend1 = BuildSpendingTransaction(scriptSig, txCredit);

    uint256 hash1 = SignatureHash(scriptPubKey, CTransaction(txSpend1), 0, SigHashType(), txCredit.vout[0].nValue);
    key.Sign(hash1, sig1, 0);
    sig1.push_back(static_cast<unsigned char>(SIGHASH_ALL));
    CScript sig2 = CScript() << sig1 << ToByteVector(pubkey);
    CMutableTransaction txSpend = BuildSpendingTransaction(sig2, txCredit);

    // Benchmark.
    while (state.KeepRunning()) {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue),
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);
    }
    std::cout << "size of txout = " << sizeof(txCredit.vout[0].scriptPubKey) << "\n";
    std::cout << "secp256k1_ecdsa_sig_verify use " << time_of_secp256k1_ecdsa_sig_verify << "cycles\n";
    std::cout << "secp256k1_ecdsa_sig_verify run " << count_of_secp256k1_ecdsa_sig_verify << "times\n";
    std::cout << "CSHA256::Write use " << time_of_CSHA256_Write << " cycles\n";
    std::cout << "CSHA256::Write run " << count_of_CSHA256_Write << " times\n";
    std::cout << "CSHA256::Write data len is " << data_len_of_CSHA256_Write/count_of_CSHA256_Write << " bytes\n";

}


BENCHMARK(MyVerifyScriptBench);
BENCHMARK(MyVerifyScriptBench_old);
