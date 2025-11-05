/*
 * LIEF MachO FatBinary Binding
 *
 * Represents a Fat/Universal Mach-O binary (or single architecture)
 */

#include "fat_binary.h"
#include "binary.h"
#include <LIEF/logging.hpp>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* fat_binary_constructor = nullptr;

Napi::Object MachOFatBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "FatBinary", {
    InstanceMethod<&MachOFatBinary::Size>("size"),
    InstanceMethod<&MachOFatBinary::At>("at"),
    InstanceMethod<&MachOFatBinary::Take>("take"),
  });

  fat_binary_constructor = new Napi::FunctionReference();
  *fat_binary_constructor = Napi::Persistent(constructor);

  return constructor;
}

MachOFatBinary::MachOFatBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<MachOFatBinary>(info), fat_binary_(nullptr) {
  // This constructor should not be called directly from JavaScript
  // FatBinary instances are created via NewInstance factory
}

Napi::Object MachOFatBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::FatBinary> fat) {
  if (!fat_binary_constructor) {
    Napi::Error::New(env, "FatBinary constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }

  Napi::Object obj = fat_binary_constructor->New({});
  MachOFatBinary* wrapper = Napi::ObjectWrap<MachOFatBinary>::Unwrap(obj);
  wrapper->fat_binary_ = std::move(fat);
  return obj;
}

Napi::Value MachOFatBinary::Size(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!fat_binary_) {
    return Napi::Number::New(env, 0);
  }

  return Napi::Number::New(env, fat_binary_->size());
}

Napi::Value MachOFatBinary::At(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!fat_binary_ || info.Length() < 1 || !info[0].IsNumber()) {
    return env.Null();
  }

  size_t index = info[0].As<Napi::Number>().Uint32Value();

  if (index >= fat_binary_->size()) {
    Napi::RangeError::New(env, "Index out of range").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get the binary at the index (returns a pointer, not ownership)
  auto* binary_ptr = fat_binary_->at(index);
  if (!binary_ptr) {
    return env.Null();
  }

  // Create a Binary wrapper - note: we need to handle the lifetime carefully
  // The FatBinary owns the actual Binary, so we pass a non-owning pointer
  return MachOBinary::NewInstance(env, binary_ptr, false);
}

Napi::Value MachOFatBinary::Take(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!fat_binary_ || info.Length() < 1 || !info[0].IsNumber()) {
    return env.Null();
  }

  size_t index = info[0].As<Napi::Number>().Uint32Value();

  if (index >= fat_binary_->size()) {
    Napi::RangeError::New(env, "Index out of range").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Take ownership of the binary at the index
  auto binary = fat_binary_->take(index);
  if (!binary) {
    return env.Null();
  }

  // Create a Binary wrapper with ownership transfer
  return MachOBinary::NewInstance(env, std::move(binary));
}

} // namespace node_lief
