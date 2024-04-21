// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>

#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>

static bool EvalChecksigTapscript(const valtype& sig, const valtype& pubkey, ScriptExecutionData& execdata, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror, bool& success)
{
    assert(sigversion == SigVersion::TAPSCRIPT);

    /*
     *  The following validation sequence is consensus critical. Please note how --
     *    upgradable public key versions precede other rules;
     *    the script execution fails when using empty signature with invalid public key;
     *    the script execution fails when using non-empty invalid signature.
     */
    success = !sig.empty();
    if (success) {
        // Implement the sigops/witnesssize ratio test.
        // Passing with an upgradable public key version is also counted.
        assert(execdata.m_validation_weight_left_init);
        execdata.m_validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if (execdata.m_validation_weight_left < 0) {
            return set_error(serror, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
        }
    }
    if (pubkey.size() == 0) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    } else if (pubkey.size() == 32) {
        if (success && !checker.CheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror)) {
            return false; // serror is set
        }
    } else {
        /*
         *  New public key version softforks should be defined before this `else` block.
         *  Generally, the new code should not do anything but failing the script execution. To avoid
         *  consensus bugs, it should not modify any existing values (including `success`).
         */
        if ((flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) != 0) {
            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
        }
    }

    return true;
}
bool TapScriptEvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, ScriptExecutionData& execdata, ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    // static const CScriptNum bnFalse(0);
    // static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    // static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    ConditionStack vfExec;
    std::vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    uint32_t opcode_pos = 0;
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;

    try
    {
        for (; pc < pend; ++opcode_pos) {
            bool fExec = vfExec.all_true();

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes (CVE-2010-5137).

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    // Compare the specified sequence number with the input.
                    if (!checker.CheckSequence(nSequence))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_NOP1: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.

                        // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                        // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                        if (vch.size() > 1 || (vch.size() == 1 && vch[0] != 1)) {
                            return set_error(serror, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
                        }
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.toggle_top();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;


                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH160)
                        CHash160().Write(vch).Finalize(vchHash);
                    else if (opcode == OP_HASH256)
                        CHash256().Write(vch).Finalize(vchHash);
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // If SCRIPT_VERIFY_CONST_SCRIPTCODE flag is set, use of OP_CODESEPARATOR is rejected in pre-segwit
                    // script, even in an unexecuted branch (this is checked above the opcode case statement).

                    // Hash starts after the code separator
                    pbegincodehash = pc;
                    execdata.m_codeseparator_pos = opcode_pos;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);

                    bool fSuccess = true;
                    if (!EvalChecksigTapscript(vchSig, vchPubKey, execdata, flags, checker, SigVersion::TAPSCRIPT, serror, fSuccess)) return false;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                break;

                case OP_CHECKSIGADD:
                {
                    // (sig num pubkey -- num)
                    if (stack.size() < 3) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const valtype& sig = stacktop(-3);
                    const CScriptNum num(stacktop(-2), fRequireMinimal);
                    const valtype& pubkey = stacktop(-1);

                    bool success = true;
                    if (!EvalChecksigTapscript(sig, pubkey, execdata, flags, checker, SigVersion::TAPSCRIPT, serror, success)) return false;
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back((num + (success ? 1 : 0)).getvch());
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    return set_error(serror, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);

                }
                break;

                default:
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }

            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

bool TapScriptEvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    ScriptExecutionData execdata;
    return TapScriptEvalScript(stack, script, flags, checker, execdata, serror);
}
