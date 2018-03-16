#include "bench.h"
#include "arith_uint256.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "config.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "fs.h"
#include "hash.h"
#include "init.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "random.h"
#include "script/script.h"
#include "script/scriptcache.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "timedata.h"
#include "tinyformat.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "versionbits.h"
#include "warnings.h"
#include "coins.h"
#include "random.h"
#include "uint256.h"
#include <key.h>
#include <script/script.h>
#include <script/sign.h>

#include <atomic>
#include <sstream>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/thread.hpp>

#include <list>
#include <vector>
#include <fcntl.h>

#define MYPATH "/Optane/chaintest"
#define FREAD   //use fread instead of the iostream
enum options {
    NUMFILE = 200,
    HASH_TABLE_SIZE = 46,  //4K / 88 = 46
    RUNS = 4000000, //Run times
    numofthread = 8  //number of multi thread
    //FILESIZE = 25*1024*1024*1024
};

namespace {
    template <class T>
        struct Compare
        {
            int operator()(const T& x, const T& k) const{
                if(x.n >= k.n) return 0;
                else return 1;
            }
        };
    struct KeyEntry {
        //char key;
        //uint256 hash;

        uint64_t Findex;
        uint64_t Bindex;
        uint32_t placeHolder1;
        uint32_t placeHolder2;
        uint32_t placeHolder3;
        uint32_t placeHolder4;
        uint32_t placeHolder5;
        uint32_t n;
        KeyEntry(uint64_t findex=0, uint64_t bindex=0, uint32_t nn=0)
            : Findex(findex), Bindex(bindex), n(nn) {}
        template <typename Stream> void Serialize(Stream &s) const {
            s << Findex;
            s << Bindex;
            s << placeHolder1;
            s << placeHolder2;
            s << placeHolder3;
            s << placeHolder4;
            s << placeHolder5;
            s << n;
        }

        template <typename Stream> void Unserialize(Stream &s) {
            s >> Findex;
            s >> Bindex;
            s >> placeHolder1;
            s >> placeHolder2;
            s >> placeHolder3;
            s >> placeHolder4;
            s >> placeHolder5;
            s >> n;
        }
    };
    struct ValueEntry {
        uint64_t placeHolder1;
        uint64_t placeHolder2;
        uint64_t placeHolder3;
        uint64_t placeHolder4;
        uint64_t placeHolder5;
        uint64_t placeHolder6;

        template <typename Stream> void Serialize(Stream &s) const {
            s << placeHolder1;
            s << placeHolder2;
            s << placeHolder3;
            s << placeHolder4;
            s << placeHolder5;
            s << placeHolder6;
        }

        template <typename Stream> void Unserialize(Stream &s) {
            s >> placeHolder1;
            s >> placeHolder2;
            s >> placeHolder3;
            s >> placeHolder4;
            s >> placeHolder5;
            s >> placeHolder6;
        }
    };
    struct KeyValue {
        KeyEntry key;
        ValueEntry value;
    };
} // namespace

static uint256 insecure_rand_seed = GetRandHash();
static FastRandomContext insecure_rand_ctx(insecure_rand_seed);
static inline uint64_t InsecureRandRange(uint64_t range) {
    return insecure_rand_ctx.randrange(range);
}
static inline uint32_t insecure_rand() {
    return insecure_rand_ctx.rand32();
}
static fs::path GetBucketPosFilename(const int findex) {
    return GetDataDir() / "blocks" / strprintf("buk%05u.dat", findex);
}
/* 
 * Example:
 * If the hash value is 64bit Uint64, we use the different bit to 
 * index the file name and bucket number. The buckets are stored 
 * sequentially in the file.
 *     63             x x-1           12 11            0
 *    |  File index    |  Bucket index  |in hash bucket|
 * Now, we use the elements of Key to indicate the filename and 
 * bucket number.
 */
#ifdef FREAD
static void FillUtxoBigHashBucket() {
    int64_t start = GetTimeMicros();

    KeyEntry entry1(0,0,0);
    KeyValue* hash_table_ = new KeyValue[HASH_TABLE_SIZE];

    try {
/*      Create numofthread files, each file capacity is 25GB.
 *      For Example: File 5's name is bigbuk00005.db.
 *      Each thread is responsible for one file.
 */
        for (int k = 0; k < numofthread; k++)   
        {
            entry1.Findex = k;
            std::cout << "Writing " << k << "file\n";
            FILE *filestr = fsbridge::fopen(strprintf("%s/bigbuk%05u.db", MYPATH, k), "wb");
            if (!filestr) {
                return;
            }

            CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

            for(uint64_t j = 0; j < 25 * 1024 * 256; j++)
            {
                if(j % (256 * 1024) ==0 )
                    std::cout << "Writing " << j / 256 / 1024 << "GB\n";
                fseek(file.Get(), 4096 * j, SEEK_SET);
                //                std::cout << "Now fp in " << ftell(file.Get()) << "\n";
                entry1.Bindex = j;
                //Fill the hash bucket with 46 UTXOs
                for(int i = 0; i < HASH_TABLE_SIZE; i++)
                {
                    entry1.n = i;
                    hash_table_[i].key = entry1;
                }
                //                std::cout << "The hashtable size = " << sizeof(hash_table_) << "\n";
                //  Write one hash bucket per time.
                file.write((char*)hash_table_, sizeof(KeyValue)*HASH_TABLE_SIZE);
#if 0
                if (fwrite(hash_table_, sizeof(KeyValue), HASH_TABLE_SIZE, filestr) != 1) {
                    std::cout << "写入失败！\n";
                }
#endif
                //                std::cout << "Now fp in " << ftell(file.Get()) << "\n";
            }
            FileCommit(file.Get());
            file.fclose();
        }
        int64_t last = GetTimeMicros();
        LogPrintf("Fill UTXO Hash Buckets: %gs\n", (last - start) * 0.000001);
    } catch (const std::exception &e) {
        LogPrintf("Failed to Fill UTXO: %s. Continuing anyway.\n", e.what());
    }
}
static bool LoadUtxoBigBucket(const int threadNum) {
    //FILE *filestr = files[findex];
    // Each thread open one file, the file name is same to the threadNum.
    FILE *filestr = fsbridge::fopen(strprintf("%s/bigbuk%05u.db", MYPATH, threadNum), "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    KeyEntry entry1(threadNum, 0, 0);
    KeyValue* hash_table_ = new KeyValue[HASH_TABLE_SIZE];

    std::cout << "I am " << threadNum << "thread\n"; 

    if (file.IsNull()) {
        LogPrintf(
            "Failed to open UTXO file from disk. Continuing anyway.\n");
        return false;
    }
    try {
        for (int i = 0; i < RUNS/numofthread; i++)
        {
            //Random access the hash bucket
            entry1.Bindex = InsecureRandRange(25*1024*256);
            entry1.n = InsecureRandRange(HASH_TABLE_SIZE);
            fseek(file.Get(), 4096 * entry1.Bindex, SEEK_SET);
            file.read((char*)hash_table_, sizeof(KeyValue)*HASH_TABLE_SIZE);
            if(hash_table_[entry1.n].key.n != entry1.n || hash_table_[entry1.n].key.Bindex != entry1.Bindex)
            {
                    LogPrintf("Failed to Load UTXO file from disk. Continuing anyway.\n");
                    LogPrintf("The n = %d, bindex = %ld, error n = %d, bindex = %ld\n", entry1.n,entry1.Bindex,hash_table_[entry1.n].key.n,hash_table_[entry1.n].key.Bindex);
            }
        }
        file.fclose();
    } catch (const std::exception &e) {
        LogPrintf("Failed to deserialize UTXO data on disk: %s. Continuing "
                  "anyway.\n",
                  e.what());
        return false;
    }

    return true;
}
#else
static void FillUtxoBigHashBucket() {
    int64_t start = GetTimeMicros();
    uint64_t length = 512 * 1024 * 1024; //512M

    std::map<KeyEntry, ValueEntry, Compare<KeyEntry>> mapDeltas;
    KeyEntry entry1(0,0,0);
    ValueEntry Value;

    try {
            entry1.Findex = 0;
            FILE *filestr = fsbridge::fopen(strprintf("%s/bigbuk%05u.db", MYPATH, 0), "wb");
            if (!filestr) {
                return;
            }

            CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

            for(uint64_t j = 0; j < 100*128*1024; j++)
            {
                if(j % (256 * 1024) ==0 )
                    std::cout << "Writing " << j / 256 / 1024 << "GB\n";
                fseek(file.Get(), 4096 * j, SEEK_SET);
                //std::cout << "Now fp in " << ftell(file.Get()) << "\n";
                entry1.Bindex = j;
                for(int i = 0; i < HASH_TABLE_SIZE; i++)
                {
                    entry1.n = i;
                    mapDeltas.insert(std::make_pair(entry1, Value));
                }
                //std::cout << "The " << mapDeltas.size() << " mapDeltas size = " << sizeof(mapDeltas) << "\n";
                file << mapDeltas;
                mapDeltas.clear();
                //std::cout << "Now fp in " << ftell(file.Get()) << "\n";
            }
            FileCommit(file.Get());
            file.fclose();
        int64_t last = GetTimeMicros();
        LogPrintf("Fill UTXO Hash Buckets: %gs\n", (last - start) * 0.000001);
    } catch (const std::exception &e) {
        LogPrintf("Failed to Fill UTXO: %s. Continuing anyway.\n", e.what());
    }
}
static bool LoadUtxoBigBucket(uint64_t findex) {
    //FILE *filestr = files[findex];
    FILE *filestr = fsbridge::fopen(strprintf("%s/bigbuk%05u.db", MYPATH, findex), "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    char buffer[4096];
    KeyEntry entry1(findex, 0, 0);
    std::map<KeyEntry, ValueEntry, Compare<KeyEntry>> mapDeltas;

    if (file.IsNull()) {
        LogPrintf(
            "Failed to open UTXO file from disk. Continuing anyway.\n");
        return false;
    }
    try {
        for (int i = 0; i < RUNS; i++)
        {
            entry1.Bindex = InsecureRandRange(100*128*1024);
            entry1.n = InsecureRandRange(HASH_TABLE_SIZE);
            fseek(file.Get(), 4096 * entry1.Bindex, SEEK_SET);
            file >> mapDeltas;
            std::map<KeyEntry, ValueEntry, Compare<KeyEntry>>::iterator itr = mapDeltas.find(entry1);
            if(itr != mapDeltas.end())
            {
                //     std::cout << "We find the UTXO, findex = " << itr->first.Findex << ", bindex = " << itr->first.Bindex << ", n = " << itr->first.n << "\n";
            }else
            {
                std::cout << "Read UTXO error\n";
            }
        }
        file.fclose();
    } catch (const std::exception &e) {
        LogPrintf("Failed to deserialize UTXO data on disk: %s. Continuing "
                  "anyway.\n",
                  e.what());
        return false;
    }

    return true;
}
#endif
static void FillUtxoHashBucket() {
    int64_t start = GetTimeMicros();
    uint64_t length = 512 * 1024 * 1024; //512M

    std::map<KeyEntry, ValueEntry, Compare<KeyEntry>> mapDeltas;
    KeyEntry entry1(0,0,0);
    ValueEntry Value;

    try {
        for (int k = 0; k < NUMFILE; k++)
        {
            entry1.Findex = k;
            if(k%10 == 0)
            {
                std::cout << "Writing " << k/2 << "GB\n";
            }
            FILE *filestr = fsbridge::fopen(strprintf("%s/buk%05u.db.new", MYPATH, k), "wb");
            if (!filestr) {
                return;
            }

            CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

            for(int j = 0; j < 128*1024; j++)
            {
                fseek(file.Get(), 4096 * j, SEEK_SET);
                //std::cout << "Now fp in " << ftell(file.Get()) << "\n";
                entry1.Bindex = j;
                for(int i = 0; i < HASH_TABLE_SIZE; i++)
                {
                    entry1.n = i;
                    mapDeltas.insert(std::make_pair(entry1, Value));
                }
                //std::cout << "The " << mapDeltas.size() << " mapDeltas size = " << sizeof(mapDeltas) << "\n";
                file << mapDeltas;
                mapDeltas.clear();
                //std::cout << "Now fp in " << ftell(file.Get()) << "\n";
            }
            FileCommit(file.Get());
            file.fclose();
            RenameOver(strprintf("%s/buk%05u.db.new", MYPATH, k),
                    strprintf("%s/buk%05u.db", MYPATH, k));
        }
        int64_t last = GetTimeMicros();
        LogPrintf("Fill UTXO Hash Buckets: %gs\n", (last - start) * 0.000001);
    } catch (const std::exception &e) {
        LogPrintf("Failed to Fill UTXO: %s. Continuing anyway.\n", e.what());
    }
}
static FILE* files[NUMFILE];
static bool LoadUTXO(uint64_t findex, uint64_t bindex, uint32_t nn) {
    //FILE *filestr = files[findex];
    FILE *filestr = fsbridge::fopen(strprintf("%s/buk%05u.db", MYPATH, findex), "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

    if (file.IsNull()) {
        LogPrintf(
            "Failed to open UTXO file from disk. Continuing anyway.\n");
        return false;
    }
    KeyEntry entry1(findex, bindex, nn);

    fseek(file.Get(), 4096 * bindex, SEEK_SET);
    std::map<KeyEntry, ValueEntry, Compare<KeyEntry>> mapDeltas;
    try {
        if(1)
        {
            file >> mapDeltas;
            std::map<KeyEntry, ValueEntry, Compare<KeyEntry>>::iterator itr = mapDeltas.find(entry1);
            if(itr != mapDeltas.end())
            {
           //     std::cout << "We find the UTXO, findex = " << itr->first.Findex << ", bindex = " << itr->first.Bindex << ", n = " << itr->first.n << "\n";
            }else
            {
                std::cout << "Read UTXO error\n";
            }
        }
        file.fclose();
    } catch (const std::exception &e) {
        LogPrintf("Failed to deserialize UTXO data on disk: %s. Continuing "
                  "anyway.\n",
                  e.what());
        return false;
    }

    return true;
}
static bool TestUTXO() {
    int64_t start = GetTimeMicros();
#if 0
    for (int i = 0; i < NUMFILE; i++)
    {
        files[i] = fsbridge::fopen(strprintf("%s/buk%05u.db", MYPATH, i), "rb");
        if (files[i] == NULL)
        {
            std::cout << "Failed to open UTXO Hash file " << i << " from disk. Continuing anyway.\n";
            return false;
        }
    }
    for (int i = 0; i < 200000; i++)
    {
        uint64_t findex = InsecureRandRange(NUMFILE);
        uint64_t bindex = InsecureRandRange(128*1024);
        uint32_t n = InsecureRandRange(HASH_TABLE_SIZE);
        LoadUTXO(findex, bindex, n);
    }
#endif
//    LoadUtxoBigBucket(1);
    boost::thread_group myHashThreads;
#if 1
    for (int i = 0; i < numofthread; i++)
        myHashThreads.create_thread(
            boost::bind(&LoadUtxoBigBucket, i));
    myHashThreads.join_all(); // ... wait until all the threads are done
#endif
    int64_t last = GetTimeMicros();
    LogPrintf("Load UTXO Hash Buckets: %gs\n", (last - start) * 0.000001);
}

extern bool fPrintToConsole;
// Right now this is only testing eviction performance in an extremely small
// mempool. Code needs to be written to generate a much wider variety of
// unique transactions for a more meaningful performance measurement.
static void MyHashDisk(benchmark::State &state) {
    fPrintToConsole = true;
//    FillUtxoBigHashBucket();
    TestUTXO();
}

BENCHMARK(MyHashDisk);

