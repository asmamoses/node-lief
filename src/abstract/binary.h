#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/Abstract/Binary.hpp>
#include "../binary_impl.h"

namespace node_lief {

/**
 * Wrapper class for LIEF::Binary exposed to JavaScript
 * Represents a generic binary executable (format-agnostic)
 */
class AbstractBinary : public Napi::ObjectWrap<AbstractBinary>, protected BinaryImpl {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  explicit AbstractBinary(const Napi::CallbackInfo& info);

  // Create a Binary instance from a LIEF binary
  static Napi::Object NewInstance(Napi::Env env, std::unique_ptr<LIEF::Binary> binary);

  // Get the underlying binary pointer
  LIEF::Binary* GetBinary() const { return owned_binary_.get(); }

 private:
  std::unique_ptr<LIEF::Binary> owned_binary_;

  // Property getters - forward to BinaryImpl
  Napi::Value GetFormat(const Napi::CallbackInfo& info) {
    return GetFormatImpl(info.Env());
  }
  Napi::Value GetEntrypoint(const Napi::CallbackInfo& info) {
    return GetEntrypointImpl(info.Env());
  }
  Napi::Value GetIsPie(const Napi::CallbackInfo& info) {
    return GetIsPieImpl(info.Env());
  }
  Napi::Value GetHasNx(const Napi::CallbackInfo& info) {
    return GetHasNxImpl(info.Env());
  }
  Napi::Value GetHeader(const Napi::CallbackInfo& info) {
    return GetHeaderImpl(info.Env());
  }
  Napi::Value GetSegments(const Napi::CallbackInfo& info) {
    return GetSegmentsImpl(info.Env());
  }

  // Methods - forward to BinaryImpl
  Napi::Value GetSections(const Napi::CallbackInfo& info) {
    return GetSectionsImpl(info.Env());
  }
  Napi::Value GetSymbols(const Napi::CallbackInfo& info) {
    return GetSymbolsImpl(info.Env());
  }
  Napi::Value GetRelocations(const Napi::CallbackInfo& info) {
    return GetRelocationsImpl(info.Env());
  }
  Napi::Value GetSymbol(const Napi::CallbackInfo& info) {
    return GetSymbolImpl(info.Env(), info);
  }
  Napi::Value PatchAddress(const Napi::CallbackInfo& info) {
    return PatchAddressImpl(info.Env(), info);
  }
  Napi::Value Write(const Napi::CallbackInfo& info) {
    return WriteImpl(info.Env(), info);
  }

  // Static helper to parse a binary file
  static Napi::Value Parse(const Napi::CallbackInfo& info);
};

} // namespace node_lief
