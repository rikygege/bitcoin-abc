#include "dbwrapper.h"
#include "random.h"
#include "uint256.h"
#include "bench.h"
#include <streams.h>
#include "script/interpreter.h"
#include "script/script.h"
#include "coins.h"
#include "scheduler.h"
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <key.h>
#include <script/script.h>
#include <script/sign.h>
// Test batch operations

extern unsigned long count_of_crc32c;
extern unsigned long size_of_crc32c;
static uint256 insecure_rand_seed = GetRandHash();
static FastRandomContext insecure_rand_ctx(insecure_rand_seed);
static inline void SeedInsecureRand(bool fDeterministic = false) {
    if (fDeterministic) {
        insecure_rand_seed = uint256();
    } else {
        insecure_rand_seed = GetRandHash();
    }
    insecure_rand_ctx = FastRandomContext(insecure_rand_seed);
}
static inline uint256 InsecureRand256() {
    return insecure_rand_ctx.rand256();
}
static inline uint64_t InsecureRandRange(uint64_t range) {
    return insecure_rand_ctx.randrange(range);
}
static inline uint32_t insecure_rand() {
    return insecure_rand_ctx.rand32();
}

static const char DB_COIN = 'C';
namespace {

struct KeyEntry {
    char key;
    uint256 hash;
    uint32_t n;
    KeyEntry(uint256 h, uint32_t nn)
        : key(DB_COIN), hash(h), n(nn) {}

    template <typename Stream> void Serialize(Stream &s) const {
        s << key;
        s << hash;
        s << VARINT(n);
    }

    template <typename Stream> void Unserialize(Stream &s) {
        s >> key;
        s >> hash;
        s >> VARINT(n);
    }
};
} // namespace
static void RandomScript(CScript &script) {
    static const opcodetype oplist[] = {
        OP_FALSE, OP_1,        OP_2,
        OP_3,     OP_CHECKSIG, OP_IF,
        OP_VERIF, OP_RETURN,   OP_CODESEPARATOR};
    script = CScript();
    int ops = (InsecureRandRange(10));
    for (int i = 0; i < ops; i++)
        script << oplist[InsecureRandRange(sizeof(oplist) / sizeof(oplist[0]))];
}
static fs::path ph = "/Optane/chainstate";
//static CDBWrapper dbw(ph, (1 << 31), false, false, 0);
static CDBWrapper dbw(ph, (8 << 20), false, false, 0);
static uint256 seed = uint256S("8e8b4cf3e4df8b332057e3e23af42ebc663b61e0495d5e7e32d85");
static uint256 seed1 = uint256S("8d75a32e8858f12307c362bcb3f76c0e645d360b0587569a49c5068efccf83fc");
static int batchsize = 200000;
//random read the database
static void getFromLevelDB(const int threadNum)
{
    int i;
    //new coin_key
    KeyEntry entry(seed, 0);
    KeyEntry entry1(seed1, 0);
    //KeyEntry entry(seed1, 0);
    Coin cres;
    std::cout << "I am " << threadNum << "thread\n"; 
    for(i = 0; i < batchsize; i++)
    {
        if(i%2 == 0)
        {
            entry.n = InsecureRandRange(1000000000);
            dbw.Read(entry, cres);
        }else
        {
            entry1.n = InsecureRandRange(1000000000);
            dbw.Read(entry1, cres);
        }
        if(cres.GetHeight() != 1)
            std::cout << sizeof(cres) << "read error\n";
    }

}

static void ReadMyDb(benchmark::State &state) {
    //fs::path ph = fs::temp_directory_path() / fs::unique_path();
    //fs::path ph = "/Optane/chainstate";
    //CDBWrapper dbw(ph, (1 << 31), false, false, 0);

    //new coin_key
    //seed grow up 10G UTXOs
    //uint256 seed = uint256S("8e8b4cf3e4df8b332057e3e23af42ebc663b61e0495d5e7e32d85");
    //seed1 grow up 10G UTXOs
    // uint256 seed1 = uint256S("8d75a32e8858f12307c362bcb3f76c0e645d360b0587569a49c5068efccf83fc");

    uint256 res;
    Coin cres;

    //random read the database
    //getFromLevelDB(1000000, 0);
    boost::thread_group myDbThreads;
    //int myDbTasks = 100000;
#if 1
    for (int i = 0; i < 5; i++)
        myDbThreads.create_thread(
            boost::bind(&getFromLevelDB, i));
    myDbThreads.join_all(); // ... wait until all the threads are done
#endif
    KeyEntry entry(seed1, 0);
    entry.n = 10000000;
    dbw.Read(entry, cres);
    std::cout << "entry = " << entry.n << ", sizeof scriptPubKey = " << sizeof(cres.GetTxOut().scriptPubKey) << "\n";
    //if(res.tostring() == in.tostring())
      //  std::cout << "read ok\n";
    if(cres.GetHeight() == 1)
        std::cout << sizeof(cres) << " read ok\n";
#if 0
    std::cout << "count_of_crc32c = " << count_of_crc32c;
    std::cout << " size_of_crc32c = " << size_of_crc32c;
    std::cout << " mean size_of_crc32c = " << size_of_crc32c/count_of_crc32c << "\n";
#endif
}

static void WriteMyDb(benchmark::State &state) {
    //fs::path ph = fs::temp_directory_path() / fs::unique_path();
    //fs::path ph = "/Optane/chainstate";
    //CDBWrapper dbw(ph, (1 << 31), false, false, 0);

    //new coin_key
    //seed grow up 10G UTXOs
    //uint256 seed = uint256S("8e8b4cf3e4df8b332057e3e23af42ebc663b61e0495d5e7e32d85");
    //seed1 grow up 10G UTXOs
    // uint256 seed1 = uint256S("8d75a32e8858f12307c362bcb3f76c0e645d360b0587569a49c5068efccf83fc");
    KeyEntry entry(seed1, 0);
    //new coin
    CTxOut txout;
    txout.nValue = Amount(int64_t(insecure_rand()) % 100000000);


    CKey key;
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
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;
    //RandomScript(txout.scriptPubKey);
    Coin newcoin(txout, 1, false);

    char key2 = 'j';
    uint256 in2 = InsecureRand256();
    char key3 = 'k';
    uint256 in3 = InsecureRand256();

    uint256 res;
    Coin cres;
    CDBBatch batch(dbw);
    //construct the database
    for(int j = 0; j < 100; j++)
    {
        for(int i = 0; i < 10000000; i ++)
        {
            entry.n = i+j*10000000;
            batch.Write(entry, newcoin);
        }
        std::cout << "writing " << j*10 << "M...\n";
        dbw.WriteBatch(batch);
        batch.Clear();
    }

/*  

    batch.Write(entry, newcoin);
    batch.Write(key2, in2);
    batch.Write(key3, in3);

    // Remove key3 before it's even been written
    batch.Erase(key3);

    dbw.WriteBatch(batch);
*/
    dbw.Sync();

    entry.n = 10000000;
    dbw.Read(entry, cres);
    std::cout << "entry = " << entry.n << ", sizeof scriptPubKey = " << sizeof(cres.GetTxOut().scriptPubKey) << "\n";
    //if(res.tostring() == in.tostring())
      //  std::cout << "read ok\n";
    if(cres.GetHeight() == 1)
        std::cout << sizeof(cres) << " read ok\n";
}
BENCHMARK(ReadMyDb);
BENCHMARK(WriteMyDb);
