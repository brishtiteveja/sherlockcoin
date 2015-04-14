// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The sherlockholmescoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//System Libraries
#include <boost/assign/list_of.hpp>
#include <vector>
#include <map>
#include <string>
#include <cassert>
#include <sstream>
#include <stdexcept>
#include <stdint.h>

//boost libraries
#include <boost/config.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/variant.hpp>
#include <boost/config.hpp>

//openssl libraries for sha256 hashing
# include <openssl/e_os2.h>

//Other Libraries (Borrowed)
#include "base58.h"  		//base58 encoding used to avoid non-alphanumerics
#include "bitcoinrpc.h"
#include "db.h"    // Important class CAddress, CAddrManm
				   // CBlockLocator, CDiskBlockIndex, CMasterKey. COutPoint, CWallet, CWalletTx defined here

#include "init.h"  // Program initiator
#include "net.h"   // Network related libraries
#include "main.h"  // Some important class and structures
#include "wallet.h"// Coin Wallet maintenance

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;    // json parser

typedef struct SHA256 {         //Derived from openssl sha structure
    unsigned int h[8];
    unsigned int Nl, Nh;
    unsigned int data[16];     //SHA left block = 16
    unsigned int num, md_length;
} SHA256_CONTEXT;

//Class fro hash creation/ hash writing
class HashCreator
{
private:
    SHA256_CONTEXT ctx;

public:
    int type;
    int version;

    HashCreator(SHA256_CONTEXT& ctx_) {
        ctx = ctx_;
    }

    void setContext(SHA256_CONTEXT& ctx_) {
    	ctx = ctx_;
    }

    HashCreator(int inType, int inVersion) {
    	type = inType;
    	version = inVersion;
    }

    HashCreator& write(const char *pch, size_t size) {
        SHA256_Update(&ctx, pch, size);
        return (*this);
    }

    uint256 GetHash() {
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        return hash2;
    }

};


/*Output: Transaction hash + output index*/
class Output
{
public:
	uint256 hash; // 256 unsigned integer
    unsigned int n;

    Output(uint256 hashIn, unsigned int nIn) {
    	hash = hashIn;
    	n = nIn;
    }

    bool IsNull() {
    	if (hash == 0 && n == (unsigned int) -1)
    		return true;
    	else
    		return false;
    }

    std::string convertToString()
    {
        return strprintf("Output(%s, %u)", hash.ToString().c_str(), n);
    }

    void print()
    {
        printf("%s\n", convertToString().c_str());
    }
};

/** Input of a transaction which includes previous transaction's output and a signature that must match the
 * output's public key.
 */
class TransactionInput
{
public:
    Output previousOutput;    //Output of previous transaction as the input of current transaction
    CScript scriptSignature;  //Object of script class of bitcoin
    unsigned int numberOfSequence;

    //1st constructor
    TransactionInput()
    {
        numberOfSequence = std::numeric_limits<unsigned int>::max();
    }

    //2nd constructor
    TransactionInput(Output prevoutIn, CScript scriptSigIn=CScript(), unsigned int numberOfSequenceInput)
    {
        previousOutput = prevoutIn;
        scriptSignature = scriptSigIn;
        numberOfSequence = numberOfSequenceInput;
    }

    //3rd constructor
    TransactionInput(uint256 previousTransactionHash, unsigned int numberofOutput, CScript scriptInputSignature=CScript(), unsigned int numberOfSequenceInput)
    {
        previousOutput = Output(previousTransactionHash, numberofOutput);
        scriptSignature = scriptInputSignature;
        numberOfSequence = numberOfSequenceInput;
    }

    bool isFinal()   // Whether final in the sequence or not
    {
        return (numberOfSequence == std::numeric_limits<unsigned int>::max());
    }

    std::string convertToString()
    {
        std::string s;
        s += "CTxIn(";
        s += previousOutput.ToString();
        if (previousOutput.IsNull())
            s += strprintf(", coinbase Signature %s", HexStr(scriptSignature).c_str()); // util function for hexadecimal string called
        else
            s += strprintf(", scriptSignature=%s", scriptSignature.ToString().substr(0,24).c_str());
        if (numberOfSequence != std::numeric_limits<unsigned int>::max())
            s += strprintf(", numberOfSequence=%u", numberOfSequence);
        s += ")";
        return s;
    }

    void print()
    {
        printf("%s\n", convertToString().c_str());
    }
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
static const int64 COIN = 100000000;
static const int64 CENT = 1000000;

class TransactionOutput
{
public:
    int64 Val;
    CScript scriptPubKey;

    TransactionOutput()
    {
        SetNull();
    }

    TransactionOutput(int64 inputValue, CScript scriptPubKeyInput)
    {
        Val = inputValue;
        scriptPubKey = scriptPubKeyInput;
    }

    void SetNull()
    {
        Val = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        if (Val == -1)
        	return true;
        else
        	return false;
    }

    uint256 GetHash() const
    {
        HashCreator ss(type, 70002); // Protocol Version = 70002 used
        ss.setContext(this);
        return ss.GetHash();
    }

    std::string convertToString() const
    {
        return strprintf("TransactionOutput(Val=%"PRI64d".%08"PRI64d", scriptPubKey=%s)", Val / COIN, Val % COIN, scriptPubKey.ToString().substr(0,30).c_str());
    }

    void print() const
    {
        printf("%s\n", convertToString().c_str());
    }
};

/** Transaction structure which has two parts: input transaction and output transaction
 */
class Transaction
{
public:
    static int64 minimumTransactionFee;
    static int64 minimumRelayTransactionFee;

    std::vector<TransactionInput> in; //Input of the transaction

    std::vector<CTxOut> out; //Output of the transaction

    unsigned int lockTime;

    Transaction()
    {
        setNull();
    }

    void setNull()
    {
        in.clear();
        out.clear();
        lockTime = 0;
    }

    bool isLast() const
    {
        if (in.empty() && out.empty()) {
        	return true;
        } else {
        	return false;
        }
    }

    uint256 GetHash() const
    {
        HashCreator ss(type, 70002); // Protocol Version = 70002 used
        ss.setContext(this);
        return ss.GetHash();
    }

    // Compares with blockHeight and blockTime to verify whether final
    bool isFinal(int blockHeight=0, int64 blockTime=0) const
    {
        if (lockTime == 0)
            return true;
        if (blockHeight == 0)
            blockHeight = -1;
        if (blockTime == 0)
        	return time(NULL);
        if (lockTime < (lockTime < LOCKTIME_THRESHOLD ? blockHeight : blockTime))
            return true;

        BOOST_FOREACH(const TransactionInput& tin, in)
            if (!tin.isFinal())
                return false;
        return true;
    }

    //Compare to find whether newer
    bool isNew(const Transaction& prev) const
    {
        if (in.size() != prev.in.size())
            return false;

        for (int i = 0; i < in.size(); i++)
            if (in[i].previousOutput != prev.in[i].previousOutput)
                return false;

        bool newer = false;
        unsigned int n = std::numeric_limits<unsigned int>::max();


        for (unsigned int i = 0; i < in.size(); i++)
        {
            if (in[i].numberOfSequence != prev.in[i].numberOfSequence)
            {
                if (in[i].numberOfSequence <= n)
                {
                    newer = false;
                    n = in[i].numberOfSequence;
                }
                if (prev.in[i].numberOfSequence < n)
                {
                    newer = true;
                    n = prev.in[i].numberOfSequence;
                }
            }
        }
        return newer;
    }

    bool isCoinBaseTransaction() const
    {
        return (in.size() == 1 && in[0].previousOutput == NULL);
    }

    //Check whether standard transaction or not
    bool isStandard() const
    {
    	if (version != 1) {
    	        return false;
    	    }

    	    if (!isFinal()) {
    	        return false;
    	    }

    	    // Extremely large transactions with lots of inputs can cost the network
    	    // almost as much to process as they cost the sender in fees, because
    	    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    	    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    	    unsigned int sz = this->GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    	    if (sz >= MAX_STANDARD_TX_SIZE) {
    	        strReason = "tx-size";
    	        return false;
    	    }

    	    BOOST_FOREACH(const CTxIn& txin, vin)
    	    {
    	        // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
    	        // pay-to-script-hash, which is 3 ~80-byte signatures, 3
    	        // ~65-byte public keys, plus a few script ops.
    	        if (txin.scriptSig.size() > 500) {
    	            strReason = "scriptsig-size";
    	            return false;
    	        }
    	        if (!txin.scriptSig.IsPushOnly()) {
    	            strReason = "scriptsig-not-pushonly";
    	            return false;
    	        }
    	        if (!txin.scriptSig.HasCanonicalPushes()) {
    	            strReason = "non-canonical-push";
    	            return false;
    	        }
    	    }
    	    BOOST_FOREACH(const CTxOut& txout, vout) {
    	        if (!::IsStandard(txout.scriptPubKey)) {
    	            strReason = "scriptpubkey";
    	            return false;
    	        }
    	        if (txout.IsDust()) {
    	            strReason = "dust";
    	            return false;
    	        }
    	    }
    	    return true;
    }

    /** Check for standard transaction types
        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
    */
    bool AreInputsStandard(CCoinsViewCache& mapInputs) const;

    /** Count ECDSA signature operations the old-fashioned (pre-0.6) way
        @return number of sigops this transaction's outputs will produce when spent
    */
    unsigned int GetLegacySigOpCount() const;

    /** Count ECDSA signature operations in pay-to-script-hash inputs.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return maximum number of sigops required to validate this transaction's inputs
     */
    unsigned int GetP2SHSigOpCount(CCoinsViewCache& mapInputs) const;

    /** Amount of sherlockholmescoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            nValueOut += txout.nValue;
            if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
                throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
        }
        return nValueOut;
    }

    /** Amount of sherlockholmescoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
     */
    int64 GetValueIn(CCoinsViewCache& mapInputs) const;

    static bool AllowFree(double dPriority)
    {
        // Large (in bytes) low-priority (new, small-coin) transactions
        // need a fee.
        return dPriority > COIN * 1000 / 250;
    }

// Apply the effects of this transaction on the UTXO set represented by view
void UpdateCoins(const CTransaction& tx, CValidationState &state, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight, const uint256 &txhash);

    int64 GetMinFee(unsigned int nBlockSize=1, bool fAllowFree=true, enum GetMinFee_mode mode=GMF_BLOCK) const;

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    std::string ToString() const
    {
        std::string str;
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%"PRIszu", vout.size=%"PRIszu", nLockTime=%u)\n",
            GetHash().ToString().c_str(),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }


    // Check whether all prevouts of this transaction are present in the UTXO set represented by view
    bool HaveInputs(CCoinsViewCache &view) const;

    // Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
    // This does not modify the UTXO set. If pvChecks is not NULL, script checks are pushed onto it
    // instead of being performed inline.
    bool CheckInputs(CValidationState &state, CCoinsViewCache &view, bool fScriptChecks = true,
                     unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
                     std::vector<CScriptCheck> *pvChecks = NULL) const;

    // Apply the effects of this transaction on the UTXO set represented by view
    void UpdateCoins(CValidationState &state, CCoinsViewCache &view, CTxUndo &txundo, int nHeight, const uint256 &txhash) const;

    // Context-independent validity checks
    bool CheckTransaction(CValidationState &state) const;

    // Try to accept this transaction into the memory pool
    bool AcceptToMemoryPool(CValidationState &state, bool fCheckInputs=true, bool fLimitFree = true, bool* pfMissingInputs=NULL, bool fRejectInsaneFee = false);

protected:
    static const CTxOut &GetOutputFor(const CTxIn& input, CCoinsViewCache& mapInputs);
};


//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
uint256 ParseHashV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const Object& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
vector<unsigned char> ParseHexV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
vector<unsigned char> ParseHexO(const Object& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", scriptPubKey.ToString()));
    out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
    {
        out.push_back(Pair("type", GetTxnOutputType(TX_NONSTANDARD)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    Array a;
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CsherlockholmescoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, Object& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (boost::int64_t)tx.nLockTime));
    Array vin;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        Object in;
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else
        {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
            Object o;
            o.push_back(Pair("asm", txin.scriptSig.ToString()));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    Array vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        Object out;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (boost::int64_t)i));
        Object o;
        ScriptPubKeyToJSON(txout.scriptPubKey, o);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (hashBlock != 0)
    {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex* pindex = (*mi).second;
            if (pindex->IsInMainChain())
            {
                entry.push_back(Pair("confirmations", 1 + nBestHeight - pindex->nHeight));
                entry.push_back(Pair("time", (boost::int64_t)pindex->nTime));
                entry.push_back(Pair("blocktime", (boost::int64_t)pindex->nTime));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

Value getrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getrawtransaction <txid> [verbose=0]\n"
            "If verbose=0, returns a string that is\n"
            "serialized, hex-encoded data for <txid>.\n"
            "If verbose is non-zero, returns an Object\n"
            "with information about <txid>.");

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    string strHex = HexStr(ssTx.begin(), ssTx.end());

    if (!fVerbose)
        return strHex;

    Object result;
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

Value listunspent(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listunspent [minconf=1] [maxconf=9999999]  [\"address\",...]\n"
            "Returns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filtered to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}");

    RPCTypeCheck(params, list_of(int_type)(int_type)(array_type));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    set<CsherlockholmescoinAddress> setAddress;
    if (params.size() > 2)
    {
        Array inputs = params[2].get_array();
        BOOST_FOREACH(Value& input, inputs)
        {
            CsherlockholmescoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid sherlockholmescoin address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

    Array results;
    vector<COutput> vecOutputs;
    assert(pwalletMain != NULL);
    pwalletMain->AvailableCoins(vecOutputs, false);
    BOOST_FOREACH(const COutput& out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        if (setAddress.size())
        {
            CTxDestination address;
            if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
                continue;

            if (!setAddress.count(address))
                continue;
        }

        int64 nValue = out.tx->vout[out.i].nValue;
        const CScript& pk = out.tx->vout[out.i].scriptPubKey;
        Object entry;
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        CTxDestination address;
        if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
        {
            entry.push_back(Pair("address", CsherlockholmescoinAddress(address).ToString()));
            if (pwalletMain->mapAddressBook.count(address))
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address]));
        }
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash())
        {
            CTxDestination address;
            if (ExtractDestination(pk, address))
            {
                const CScriptID& hash = boost::get<const CScriptID&>(address);
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount",ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations",out.nDepth));
        results.push_back(entry);
    }

    return results;
}

void checkType(const Array& parameters, const list<Value_type>& ExpectedTypes, bool NullAllowance)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, ExpectedTypes)
    {
        if (parameters.size() <= i)
            break;

        const Value& v = parameters[i];
        if (!((v.type() == t) || (NullAllowance && (v.type() == null_type))))
        {
            cout << "Type error." << endl;
        }
        i++;
    }
}

void checkValidity(const Array& params,
                  const list<Value_type>& Expected)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, Expected)
    {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || ((v.type() == NULL))))
        {
        	cout << "Type error." << endl;
        }
        i++;
    }
}

Value makeTransaction(const Config::Array_type& parameters, bool helpOptions)
{
    if (helpOptions || parameters.size() != 2)
        throw runtime_error("Transaction is not proper");

    Array inputs = parameters[0].get_array();
    Object sendTo = parameters[1].get_obj();

    CTransaction rawTx;

    BOOST_FOREACH(const Value& input, inputs)
    {
        const Object& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != int_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(txid, nOutput));
        rawTx.vin.push_back(in);
    }

    set<CsherlockholmescoinAddress> setAddress;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CsherlockholmescoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid sherlockholmescoin address: ")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64 nAmount = AmountFromValue(s.value_);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;
    return HexStr(ss.begin(), ss.end());
}

Value decoderawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decoderawtransaction <hex string>\n"
            "Return a JSON object representing the serialized, hex-encoded transaction.");

    vector<unsigned char> txData(ParseHexV(params[0], "argument"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    Object result;
    TxToJSON(tx, 0, result);

    return result;
}

Value signrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "signrawtransaction <hex string> [{\"txid\":txid,\"vout\":n,\"scriptPubKey\":hex,\"redeemScript\":hex},...] [<privatekey1>,...] [sighashtype=\"ALL\"]\n"
            "Sign inputs for raw transaction (serialized, hex-encoded).\n"
            "Second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "Third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
            "Fourth optional argument is a string that is one of six values; ALL, NONE, SINGLE or\n"
            "ALL|ANYONECANPAY, NONE|ANYONECANPAY, SINGLE|ANYONECANPAY.\n"
            "Returns json object with keys:\n"
            "  hex : raw transaction with signature(s) (hex-encoded string)\n"
            "  complete : 1 if transaction has a complete set of signature (0 if not)"
            + HelpRequiringPassphrase());

    RPCTypeCheck(params, list_of(str_type)(array_type)(array_type)(str_type), true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CTransaction> txVariants;
    while (!ssData.empty())
    {
        try {
            CTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (std::exception &e) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.GetCoins(prevHash, coins); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && params[2].type() != null_type)
    {
        fGivenKeys = true;
        Array keys = params[2].get_array();
        BOOST_FOREACH(Value k, keys)
        {
            CsherlockholmescoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            tempKeystore.AddKey(key);
        }
    }
    else
        EnsureWalletIsUnlocked();

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && params[1].type() != null_type)
    {
        Array prevTxs = params[1].get_array();
        BOOST_FOREACH(Value& p, prevTxs)
        {
            if (p.type() != obj_type)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            Object prevOut = p.get_obj();

            RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type));

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            CCoins coins;
            if (view.GetCoins(txid, coins)) {
                if (coins.IsAvailable(nOut) && coins.vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + coins.vout[nOut].scriptPubKey.ToString() + "\nvs:\n"+
                        scriptPubKey.ToString();
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                // what todo if txid is known, but the actual output isn't?
            }
            if ((unsigned int)nOut >= coins.vout.size())
                coins.vout.resize(nOut+1);
            coins.vout[nOut].scriptPubKey = scriptPubKey;
            coins.vout[nOut].nValue = 0; // we don't know the actual output value
            view.SetCoins(txid, coins);

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash())
            {
                RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type)("redeemScript",str_type));
                Value v = find_value(prevOut, "redeemScript");
                if (!(v == Value::null))
                {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && params[3].type() != null_type)
    {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        CCoins coins;
        if (!view.GetCoins(txin.prevout.hash, coins) || !coins.IsAvailable(txin.prevout.n))
        {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coins.vout[txin.prevout.n].scriptPubKey;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CTransaction& txv, txVariants)
        {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifyScript(txin.scriptSig, prevPubKey, mergedTx, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC, 0))
            fComplete = false;
    }

    Object result;
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
    result.push_back(Pair("hex", HexStr(ssTx.begin(), ssTx.end())));
    result.push_back(Pair("complete", fComplete));

    return result;
}

Value sendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "sendrawtransaction <hex string> [allowhighfees=false]\n"
            "Submits raw transaction (serialized, hex-encoded) to local node and network.");

    // parse hex string from parameter
    vector<unsigned char> txData(ParseHexV(params[0], "parameter"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    // deserialize binary data stream
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    uint256 hashTx = tx.GetHash();

    bool fHave = false;
    CCoinsViewCache &view = *pcoinsTip;
    CCoins existingCoins;
    {
        fHave = view.GetCoins(hashTx, existingCoins);
        if (!fHave) {
            // push to local node
            CValidationState state;
            if (!tx.AcceptToMemoryPool(state, true, false, NULL, !fOverrideFees))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX rejected"); // TODO: report validation state
        }
    }
    if (fHave) {
        if (existingCoins.nHeight < 1000000000)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "transaction already in block chain");
        // Not in block, but already in the memory pool; will drop
        // through to re-relay it.
    } else {
        SyncWithWallets(hashTx, tx, NULL, true);
    }
    RelayTransaction(tx, hashTx);

    return hashTx.GetHex();
}

Value getnormalizedtxid(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getnormalizedtxid <hex string>\n"
            "Return the normalized transaction ID.");

    // parse hex string from parameter
    vector<unsigned char> txData(ParseHexV(params[0], "parameter"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;

    // deserialize binary data stream
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    uint256 hashNormalized = tx.GetNormalizedHash();

    return hashNormalized.GetHex();
}
