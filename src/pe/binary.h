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
  static Napi::Value NewInstance(Napi::Env env, std::unique_ptr<LIEF::PE::Binary> binary);
  explicit PEBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::PE::Binary> binary_;

  // Abstract properties (inherited from LIEF::Binary)
  Napi::Value GetFormat(const Napi::CallbackInfo& info);
  Napi::Value GetEntrypoint(const Napi::CallbackInfo& info);
  Napi::Value GetIsPie(const Napi::CallbackInfo& info);
  Napi::Value GetHasNx(const Napi::CallbackInfo& info);

  // PE-specific property getters
  Napi::Value GetOptionalHeader(const Napi::CallbackInfo& info);

  // Methods
  Napi::Value GetSection(const Napi::CallbackInfo& info);
  Napi::Value Write(const Napi::CallbackInfo& info);
};

} // namespace node_lief
