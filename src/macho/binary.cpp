/*
 * LIEF MachO Binary Binding
 *
 * Provides MachO-specific binary manipulation for repacking Bun binaries
 */

#include "binary.h"
#include "header.h"
#include "../abstract/segment.h"
#include "../abstract/section.h"
#include <LIEF/logging.hpp>

namespace node_lief {

// Static storage for constructor
static Napi::FunctionReference* macho_binary_constructor = nullptr;

Napi::Object MachOBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Abstract properties
    InstanceAccessor<&MachOBinary::GetFormat>("format"),
    InstanceAccessor<&MachOBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&MachOBinary::GetIsPie>("isPie"),
    InstanceAccessor<&MachOBinary::GetHasNx>("hasNx"),
    // MachO-specific properties
    InstanceAccessor<&MachOBinary::GetHasCodeSignature>("hasCodeSignature"),
    InstanceAccessor<&MachOBinary::GetHeader>("header"),
    // Methods - camelCase (JavaScript convention)
    InstanceMethod<&MachOBinary::GetSegment>("getSegment"),
    InstanceMethod<&MachOBinary::GetSections>("sections"),
    InstanceMethod<&MachOBinary::GetSymbols>("symbols"),
    InstanceMethod<&MachOBinary::RemoveSignature>("removeSignature"),
    InstanceMethod<&MachOBinary::ExtendSegment>("extendSegment"),
    InstanceMethod<&MachOBinary::Write>("write"),
  });

  macho_binary_constructor = new Napi::FunctionReference();
  *macho_binary_constructor = Napi::Persistent(constructor);

  return constructor;
}

MachOBinary::MachOBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<MachOBinary>(info),
      binary_(nullptr),
      binary_ptr_(nullptr),
      owns_binary_(false) {
  // This constructor should not be called directly from JavaScript
  // Binary instances are created via NewInstance factory methods
}

Napi::Object MachOBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::MachO::Binary> binary) {
  if (!macho_binary_constructor) {
    Napi::Error::New(env, "MachOBinary constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }

  Napi::Object obj = macho_binary_constructor->New({});
  MachOBinary* wrapper = Napi::ObjectWrap<MachOBinary>::Unwrap(obj);
  wrapper->binary_ = std::move(binary);
  wrapper->binary_ptr_ = nullptr;
  wrapper->owns_binary_ = true;
  return obj;
}

Napi::Object MachOBinary::NewInstance(Napi::Env env, LIEF::MachO::Binary* binary, bool owns) {
  if (!macho_binary_constructor) {
    Napi::Error::New(env, "MachOBinary constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }

  Napi::Object obj = macho_binary_constructor->New({});
  MachOBinary* wrapper = Napi::ObjectWrap<MachOBinary>::Unwrap(obj);

  if (owns) {
    wrapper->binary_ = std::unique_ptr<LIEF::MachO::Binary>(binary);
    wrapper->binary_ptr_ = nullptr;
    wrapper->owns_binary_ = true;
  } else {
    wrapper->binary_ = nullptr;
    wrapper->binary_ptr_ = binary;
    wrapper->owns_binary_ = false;
  }

  return obj;
}

// Abstract properties implementation
Napi::Value MachOBinary::GetFormat(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::String::New(env, "MachO");
}

Napi::Value MachOBinary::GetEntrypoint(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* binary = GetBinary();
  if (!binary) return env.Null();
  return Napi::BigInt::New(env, binary->entrypoint());
}

Napi::Value MachOBinary::GetIsPie(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* binary = GetBinary();
  if (!binary) return env.Null();
  return Napi::Boolean::New(env, binary->is_pie());
}

Napi::Value MachOBinary::GetHasNx(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto* binary = GetBinary();
  if (!binary) return env.Null();
  return Napi::Boolean::New(env, binary->has_nx());
}

// MachO-specific properties
Napi::Value MachOBinary::GetHasCodeSignature(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary) {
    return env.Null();
  }

  return Napi::Boolean::New(env, binary->has_code_signature());
}

Napi::Value MachOBinary::GetHeader(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary) {
    return env.Null();
  }

  return MachOHeader::NewInstance(env, &binary->header());
}

Napi::Value MachOBinary::GetSegment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary || info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string segment_name = info[0].As<Napi::String>();
  auto* segment = binary->get_segment(segment_name);

  if (!segment) {
    return env.Null();
  }

  return Segment::NewInstance(env, segment);
}

Napi::Value MachOBinary::GetSections(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary) {
    return Napi::Array::New(env);
  }

  Napi::Array sections_array = Napi::Array::New(env);
  uint32_t idx = 0;

  try {
    for (auto& section : binary->sections()) {
      sections_array[idx++] = Section::NewInstance(env, &section);
    }
  } catch (...) {
    // Return empty array on error
  }

  return sections_array;
}

Napi::Value MachOBinary::GetSymbols(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary) {
    return Napi::Array::New(env);
  }

  Napi::Array symbols_array = Napi::Array::New(env);
  uint32_t idx = 0;

  try {
    for (auto& symbol : binary->symbols()) {
      // For now, just create objects with name property
      Napi::Object symbol_obj = Napi::Object::New(env);
      symbol_obj.Set("name", Napi::String::New(env, symbol.name()));
      symbols_array[idx++] = symbol_obj;
    }
  } catch (...) {
    // Return empty array on error
  }

  return symbols_array;
}

Napi::Value MachOBinary::RemoveSignature(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary) {
    return env.Undefined();
  }

  try {
    binary->remove_signature();
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to remove signature: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

Napi::Value MachOBinary::ExtendSegment(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary || info.Length() < 2) {
    Napi::TypeError::New(env, "extend_segment requires a segment and size")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  // Get segment from first argument (must be a Segment wrapper)
  Napi::Object seg_obj = info[0].As<Napi::Object>();
  Segment* seg_wrapper = nullptr;

  try {
    seg_wrapper = Napi::ObjectWrap<Segment>::Unwrap(seg_obj);
  } catch (...) {
    Napi::TypeError::New(env, "First argument must be a Segment object")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  if (!seg_wrapper) {
    return Napi::Boolean::New(env, false);
  }

  LIEF::MachO::SegmentCommand* segment = seg_wrapper->GetSegment();
  if (!segment) {
    return Napi::Boolean::New(env, false);
  }

  // Get size from second argument
  uint64_t size = 0;
  if (info[1].IsBigInt()) {
    bool lossless = false;
    size = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
  } else if (info[1].IsNumber()) {
    size = static_cast<uint64_t>(info[1].As<Napi::Number>().Uint32Value());
  } else {
    Napi::TypeError::New(env, "Size must be a number or BigInt")
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }

  try {
    // extend_segment takes a const reference, not a pointer
    bool result = binary->extend_segment(*segment, size);
    return Napi::Boolean::New(env, result);
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to extend segment: ") + e.what())
        .ThrowAsJavaScriptException();
    return Napi::Boolean::New(env, false);
  }
}

Napi::Value MachOBinary::Write(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto* binary = GetBinary();
  if (!binary || info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "write() requires an output file path")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string output_path = info[0].As<Napi::String>();

  try {
    // Use static Builder::write for MachO binaries
    LIEF::MachO::Builder::write(*binary, output_path);
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to write binary: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

} // namespace node_lief
