#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/Abstract/Binary.hpp>

namespace node_lief {

/**
 * Wrapper class for LIEF::Binary exposed to JavaScript
 * Represents a generic binary executable (format-agnostic)
 */
class AbstractBinary : public Napi::ObjectWrap<AbstractBinary> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  explicit AbstractBinary(const Napi::CallbackInfo& info);

  // Create a Binary instance from a LIEF binary
  static Napi::Object NewInstance(Napi::Env env, std::unique_ptr<LIEF::Binary> binary);

  // Get the underlying binary pointer
  LIEF::Binary* GetBinary() const { return binary_.get(); }

 private:
  std::unique_ptr<LIEF::Binary> binary_;

  // Property getters
  Napi::Value GetFormat(const Napi::CallbackInfo& info);
  Napi::Value GetEntrypoint(const Napi::CallbackInfo& info);
  Napi::Value GetIsPie(const Napi::CallbackInfo& info);
  Napi::Value GetHasNx(const Napi::CallbackInfo& info);
  Napi::Value GetHeader(const Napi::CallbackInfo& info);
  Napi::Value GetSegments(const Napi::CallbackInfo& info);

  // Methods
  Napi::Value GetSections(const Napi::CallbackInfo& info);
  Napi::Value GetSymbols(const Napi::CallbackInfo& info);
  Napi::Value GetRelocations(const Napi::CallbackInfo& info);
  Napi::Value GetSymbol(const Napi::CallbackInfo& info);
  Napi::Value PatchAddress(const Napi::CallbackInfo& info);
  Napi::Value Write(const Napi::CallbackInfo& info);

  // Static helper to parse a binary file
  static Napi::Value Parse(const Napi::CallbackInfo& info);
};

} // namespace node_lief
