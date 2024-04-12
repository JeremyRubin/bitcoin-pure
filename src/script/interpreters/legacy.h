// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_LEGACY_INTERPRETER_H
#define BITCOIN_SCRIPT_LEGACY_INTERPRETER_H

#include <hash.h>
#include <script/script_error.h>
#include <span.h>
#include <primitives/transaction.h>

#include <optional>
#include <vector>
#include <stdint.h>

bool LegacyEvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, ScriptExecutionData& execdata, ScriptError* error = nullptr);
bool LegacyEvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* error = nullptr);
bool LegacyVerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror = nullptr);

#endif