#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <iostream>
#include "nan.h"

// Main Imports
#include "algorithms/main/allium/allium.h"
#include "algorithms/main/blake/blake.h"
#include "algorithms/main/blake/blake2s.h"
#include "algorithms/main/c11/c11.h"
#include "algorithms/main/curvehash/curvehash.h"
#include "algorithms/main/equihash/equihash.h"
#include "algorithms/main/fugue/fugue.h"
#include "algorithms/main/ghostrider/ghostrider.h"
#include "algorithms/main/groestl/groestl.h"
#include "algorithms/main/keccak/keccak.h"
#include "algorithms/main/lyra2re/lyra2re.h"
#include "algorithms/main/minotaur/minotaur.h"
#include "algorithms/main/nist5/nist5.h"
#include "algorithms/main/quark/quark.h"
#include "algorithms/main/qubit/qubit.h"
#include "algorithms/main/scrypt/scrypt.h"
#include "algorithms/main/sha256d/sha256d.h"
#include "algorithms/main/sha512256d/sha512256d.h"
#include "algorithms/main/skein/skein.h"
#include "algorithms/main/verthash/verthash.h"
#include "algorithms/main/x11/x11.h"
#include "algorithms/main/x13/x13.h"
#include "algorithms/main/x15/x15.h"
#include "algorithms/main/x16r/x16r.h"
#include "algorithms/main/x16rt/x16rt.h"
#include "algorithms/main/x17/x17.h"

// ProgPow Imports
#include "algorithms/main/evrprogpow/evrprogpow.h"
#include "algorithms/main/evrprogpow/evrprogpow.hpp"
#include "algorithms/main/evrprogpow/evrprogpow_progpow.hpp"
#include "algorithms/main/firopow/firopow.h"
#include "algorithms/main/firopow/firopow.hpp"
#include "algorithms/main/firopow/firopow_progpow.hpp"
#include "algorithms/main/kawpow/kawpow.h"
#include "algorithms/main/kawpow/kawpow.hpp"
#include "algorithms/main/kawpow/kawpow_progpow.hpp"
#include "algorithms/main/meowpow/meowpow.h"
#include "algorithms/main/meowpow/meowpow.hpp"
#include "algorithms/main/meowpow/meowpow_progpow.hpp"
#include "algorithms/main/meraki/meraki.h"
#include "algorithms/main/meraki/meraki.hpp"
#include "algorithms/main/meraki/meraki_progpow.hpp"

// Common Imports
#include "algorithms/main/common/ethash/helpers.hpp"

#include "algorithms/main/secp256k1/include/secp256k1.h"
#include "algorithms/main/secp256k1/include/secp256k1_ecdh.h"
#include "algorithms/main/secp256k1/include/secp256k1_preallocated.h"
#include "algorithms/main/secp256k1/include/secp256k1_schnorrsig.h"

using namespace node;
using namespace v8;

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)
const char* ToCString(const Nan::Utf8String& value) {
  return *value ? *value : "<string conversion failed>";
}

// Allium Algorithm
NAN_METHOD(allium) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  allium_hash(input, output);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Blake Algorithm
NAN_METHOD(blake) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  blake_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Blake Algorithm
NAN_METHOD(blake2s) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  blake2s_hash(input, output);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// C11 Algorithm
NAN_METHOD(c11) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  c11_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// CurveHash Algorithm
NAN_METHOD(curvehash) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  curve_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Equihash Algorithm
NAN_METHOD(equihash) {

  // Handle Main Scope
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  // Check Arguments for Errors [1]
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");
  if (!info[3]->IsInt32() || !info[4]->IsInt32())
    return THROW_ERROR_EXCEPTION("The fourth and fifth parameters should be equihash parameters (n, k)");

  // Define Passed Parameters
  Isolate *argsIsolate = info.GetIsolate();
  Local<Context> context = argsIsolate->GetCurrentContext();
  Local<Object> header = info[0]->ToObject(context).ToLocalChecked();
  Local<Object> solution = info[1]->ToObject(context).ToLocalChecked();

  // Check Arguments for Errors [2]
  if (!Buffer::HasInstance(header) || !Buffer::HasInstance(solution))
    return THROW_ERROR_EXCEPTION("The first two arguments should be buffer objects");
  if (!info[2]->IsString())
    return THROW_ERROR_EXCEPTION("The third argument should be the personalization string");

  // Header Length !== 140
  const char *hdr = Buffer::Data(header);
  if (Buffer::Length(header) != 140) {
    info.GetReturnValue().Set(false);
    return;
  }

  // Process Passed Parameters
  const char *soln = Buffer::Data(solution);
  vector<unsigned char> vecSolution(soln, soln + Buffer::Length(solution));
  Nan::Utf8String str(info[2]);
  const char* personalizationString = ToCString(str);
  unsigned int N = info[3].As<Uint32>()->Value();
  unsigned int K = info[4].As<Uint32>()->Value();

  // Hash Input Data and Check if Valid Solution
  bool isValid;
  crypto_generichash_blake2b_state state;
  EhInitialiseState(N, K, state, personalizationString);
  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);
  EhIsValidSolution(N, K, state, vecSolution, isValid);
  info.GetReturnValue().Set(isValid);
}

// Evrprogpow Algorithm
NAN_METHOD(evrprogpow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static evrprogpow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = evrprogpow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = evrprogpow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = evrprogpow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Firopow Algorithm
NAN_METHOD(firopow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static firopow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = firopow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = firopow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = firopow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Fugue Algorithm
NAN_METHOD(fugue) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  fugue_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Ghostrider Algorithm
NAN_METHOD(ghostrider) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  ghostrider_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Groestl Algorithm
NAN_METHOD(groestl) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  groestl_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Groestl Myriad Algorithm
NAN_METHOD(groestlmyriad) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  groestlmyriad_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Kawpow Algorithm
NAN_METHOD(kawpow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static kawpow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = kawpow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = kawpow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = kawpow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Keccak Algorithm
NAN_METHOD(keccak) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  keccak_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Lyra2re Algorithm
NAN_METHOD(lyra2re) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide exactly one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  lyra2re_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Meowpow Algorithm
NAN_METHOD(meowpow) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static meowpow_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = meowpow_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = meowpow_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = meowpow_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Meraki Algorithm
NAN_METHOD(meraki) {

  // Check Arguments for Errors
  if (info.Length() < 5)
    return THROW_ERROR_EXCEPTION("You must provide five arguments.");

  // Process/Define Passed Parameters [1]
  const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
  int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
  ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

  // Process/Define Passed Parameters [2]
  static meraki_main::epoch_context_ptr context{nullptr, nullptr};
  const auto epoch_number = meraki_main::get_epoch_number(block_height);
  if (!context || context->epoch_number != epoch_number)
      context = meraki_main::create_epoch_context(epoch_number);

  // Hash Input Data and Check if Valid Solution
  bool is_valid = meraki_progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);
  if (is_valid) info.GetReturnValue().Set(Nan::True());
  else info.GetReturnValue().Set(Nan::False());
}

// Minotaur Algorithm
NAN_METHOD(minotaur) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  minotaur_hash(input, output, input_len, false);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// MinotaurX Algorithm
NAN_METHOD(minotaurx) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  minotaur_hash(input, output, input_len, true);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Nist5 Algorithm
NAN_METHOD(nist5) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  nist5_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Quark Algorithm
NAN_METHOD(quark) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  quark_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Qubit Algorithm
NAN_METHOD(qubit) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  qubit_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Scrypt Algorithm
NAN_METHOD(scrypt) {

  // Handle Main Scope
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  // Check Arguments for Errors [1]
  if (info.Length() < 3)
    return THROW_ERROR_EXCEPTION("You must provide an input buffer, as well as an nValue and rValue.");
  if (!info[1]->IsInt32() || !info[2]->IsInt32())
    return THROW_ERROR_EXCEPTION("The first and second parameters should be scrypt parameters (n, r)");

  // Define Passed Parameters
  Isolate *argsIsolate = info.GetIsolate();
  Local<Context> context = argsIsolate->GetCurrentContext();
  Local<Object> header = info[0]->ToObject(context).ToLocalChecked();
  unsigned int N = info[1].As<Uint32>()->Value();
  unsigned int R = info[2].As<Uint32>()->Value();

  // Check Arguments for Errors [2]
  if (!Buffer::HasInstance(header))
    return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(header);
  uint32_t input_len = Buffer::Length(header);
  char output[32];

  // Hash Input Data and Return Output
  scrypt_N_R_1_256(input, output, N, R, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Sha256d Algorithm
NAN_METHOD(sha256d) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  sha256d_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Sha512256d Algorithm
NAN_METHOD(sha512256d) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t nonce = info[1]->IntegerValue(Nan::GetCurrentContext()).FromJust();
  char output[32];

  // Hash Input Data and Return Output
  sha512256d_hash(input, output, nonce);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Skein Algorithm
NAN_METHOD(skein) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  skein_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// Verthash Algorithm
NAN_METHOD(verthash) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  verthash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X11 Algorithm
NAN_METHOD(x11) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x11_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X13 Algorithm
NAN_METHOD(x13) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x13_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X15 Algorithm
NAN_METHOD(x15) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x15_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X16r Algorithm
NAN_METHOD(x16r) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x16r_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X16rt Algorithm
NAN_METHOD(x16rt) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x16rt_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X16rv2 Algorithm
NAN_METHOD(x16rv2) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x16rv2_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}

// X17 Algorithm
NAN_METHOD(x17) {

  // Check Arguments for Errors
  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide one argument.");

  // Process/Define Passed Parameters
  char * input = Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  uint32_t input_len = Buffer::Length(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  char output[32];

  // Hash Input Data and Return Output
  x17_hash(input, output, input_len);
  info.GetReturnValue().Set(Nan::CopyBuffer(output, 32).ToLocalChecked());
}


NAN_MODULE_INIT(init) {
  Nan::Set(target, Nan::New("allium").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(allium)).ToLocalChecked());
  Nan::Set(target, Nan::New("blake").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(blake)).ToLocalChecked());
  Nan::Set(target, Nan::New("blake2s").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(blake2s)).ToLocalChecked());
  Nan::Set(target, Nan::New("c11").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(c11)).ToLocalChecked());
  Nan::Set(target, Nan::New("curvehash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(curvehash)).ToLocalChecked());
  Nan::Set(target, Nan::New("equihash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(equihash)).ToLocalChecked());
  Nan::Set(target, Nan::New("evrprogpow").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(evrprogpow)).ToLocalChecked());
  Nan::Set(target, Nan::New("firopow").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(firopow)).ToLocalChecked());
  Nan::Set(target, Nan::New("fugue").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fugue)).ToLocalChecked());
  Nan::Set(target, Nan::New("ghostrider").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(ghostrider)).ToLocalChecked());
  Nan::Set(target, Nan::New("groestl").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestl)).ToLocalChecked());
  Nan::Set(target, Nan::New("groestlmyriad").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
  Nan::Set(target, Nan::New("kawpow").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(kawpow)).ToLocalChecked());
  Nan::Set(target, Nan::New("keccak").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(keccak)).ToLocalChecked());
  Nan::Set(target, Nan::New("lyra2re").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(lyra2re)).ToLocalChecked());
  Nan::Set(target, Nan::New("minotaur").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(minotaur)).ToLocalChecked());
  Nan::Set(target, Nan::New("minotaurx").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(minotaurx)).ToLocalChecked());
  Nan::Set(target, Nan::New("meowpow").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(meowpow)).ToLocalChecked());
  Nan::Set(target, Nan::New("meraki").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(meraki)).ToLocalChecked());
  Nan::Set(target, Nan::New("nist5").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(nist5)).ToLocalChecked());
  Nan::Set(target, Nan::New("quark").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(quark)).ToLocalChecked());
  Nan::Set(target, Nan::New("qubit").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(qubit)).ToLocalChecked());
  Nan::Set(target, Nan::New("scrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scrypt)).ToLocalChecked());
  Nan::Set(target, Nan::New("sha256d").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(sha256d)).ToLocalChecked());
  Nan::Set(target, Nan::New("sha512256d").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(sha512256d)).ToLocalChecked());
  Nan::Set(target, Nan::New("skein").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(skein)).ToLocalChecked());
  Nan::Set(target, Nan::New("verthash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(verthash)).ToLocalChecked());
  Nan::Set(target, Nan::New("x11").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x11)).ToLocalChecked());
  Nan::Set(target, Nan::New("x13").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x13)).ToLocalChecked());
  Nan::Set(target, Nan::New("x15").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x15)).ToLocalChecked());
  Nan::Set(target, Nan::New("x16r").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x16r)).ToLocalChecked());
  Nan::Set(target, Nan::New("x16rt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x16rt)).ToLocalChecked());
  Nan::Set(target, Nan::New("x16rv2").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x16rv2)).ToLocalChecked());
  Nan::Set(target, Nan::New("x17").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x17)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
