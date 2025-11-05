/*
 * LIEF MachO parse() function
 */

#include "fat_binary.h"
#include "binary.h"
#include <napi.h>
#include <LIEF/MachO.hpp>

namespace node_lief {

Napi::Value MachOParse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "parse() requires a file path string")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file - returns FatBinary which may contain multiple architectures
  auto fat_binary = LIEF::MachO::Parser::parse(filename);
  if (!fat_binary) {
    Napi::Error::New(env, "Failed to parse MachO binary file").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Return the FatBinary wrapper
  return MachOFatBinary::NewInstance(env, std::move(fat_binary));
}

} // namespace node_lief
