#pragma once

#include <napi.h>
#include <memory>
#include <LIEF/MachO.hpp>

namespace node_lief {

/**
 * MachO FatBinary wrapper
 * Represents a MachO Fat/Universal binary (or single architecture)
 */
class MachOFatBinary : public Napi::ObjectWrap<MachOFatBinary> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from parsed FatBinary
  static Napi::Object NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::FatBinary> fat);

  // Constructor (must be public for ObjectWrap)
  explicit MachOFatBinary(const Napi::CallbackInfo& info);

 private:
  std::unique_ptr<LIEF::MachO::FatBinary> fat_binary_;

  // Methods
  Napi::Value Size(const Napi::CallbackInfo& info);
  Napi::Value At(const Napi::CallbackInfo& info);
  Napi::Value Take(const Napi::CallbackInfo& info);
};

} // namespace node_lief
