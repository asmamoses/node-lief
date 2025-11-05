#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/PE.hpp>

namespace node_lief {

/**
 * PE-specific Binary wrapper
 * Provides PE format-specific functionality for Windows executables
 */
class PEBinary : public Napi::ObjectWrap<PEBinary> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  explicit PEBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::PE::Binary> binary_;

  // Methods
  Napi::Value GetSection(const Napi::CallbackInfo& info);
  Napi::Value Write(const Napi::CallbackInfo& info);
};

} // namespace node_lief
