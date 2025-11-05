#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/ELF.hpp>

namespace node_lief {

/**
 * ELF-specific Binary wrapper
 * Provides ELF format-specific functionality
 */
class ELFBinary : public Napi::ObjectWrap<ELFBinary> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  explicit ELFBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::ELF::Binary> binary_;

  // Methods
  Napi::Value GetSection(const Napi::CallbackInfo& info);
  Napi::Value Write(const Napi::CallbackInfo& info);
};

} // namespace node_lief
