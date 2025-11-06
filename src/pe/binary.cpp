/*
 * LIEF PE Binary Binding
 *
 * Provides PE-specific binary manipulation for Windows executables
 */

#include "binary.h"
#include "optional_header.h"
#include "../abstract/section.h"

namespace node_lief {

// Static storage for PE Binary constructor
static Napi::FunctionReference* pe_binary_constructor = nullptr;

Napi::Object PEBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Abstract properties
    InstanceAccessor<&PEBinary::GetFormat>("format"),
    InstanceAccessor<&PEBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&PEBinary::GetIsPie>("isPie"),
    InstanceAccessor<&PEBinary::GetHasNx>("hasNx"),
    // PE-specific properties
    InstanceAccessor<&PEBinary::GetOptionalHeader>("optionalHeader"),
    // Methods
    InstanceMethod<&PEBinary::GetSection>("get_section"),
    InstanceMethod<&PEBinary::Write>("write"),
  });

  pe_binary_constructor = new Napi::FunctionReference();
  *pe_binary_constructor = Napi::Persistent(constructor);

  exports.Set("Binary", constructor);
  return exports;
}

Napi::Value PEBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::PE::Binary> binary) {
  if (!pe_binary_constructor) {
    Napi::Error::New(env, "PEBinary constructor not initialized").ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Object obj = pe_binary_constructor->New({});
  PEBinary* wrapper = PEBinary::Unwrap(obj);
  wrapper->binary_ = std::move(binary);
  return obj;
}

PEBinary::PEBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<PEBinary>(info), binary_(nullptr) {
  Napi::Env env = info.Env();

  // Allow construction with no arguments for NewInstance pattern
  if (info.Length() == 0) {
    return;
  }

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "PEBinary constructor requires a string file path").ThrowAsJavaScriptException();
    return;
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file
  auto parsed = LIEF::PE::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse PE binary file").ThrowAsJavaScriptException();
    return;
  }

  binary_ = std::move(parsed);
}

Napi::Value PEBinary::GetSection(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_ || info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string section_name = info[0].As<Napi::String>();
  auto* section = binary_->get_section(section_name);

  if (!section) {
    return env.Null();
  }

  return Section::NewInstance(env, section);
}

Napi::Value PEBinary::Write(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_ || info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "write() requires an output file path")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string output_path = info[0].As<Napi::String>();

  try {
    binary_->write(output_path);
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to write binary: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

Napi::Value PEBinary::GetOptionalHeader(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  return OptionalHeader::NewInstance(env, &binary_->optional_header());
}

// Abstract property implementations

Napi::Value PEBinary::GetFormat(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), "PE");
}

Napi::Value PEBinary::GetEntrypoint(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!binary_) return env.Undefined();
  return Napi::BigInt::New(env, binary_->entrypoint());
}

Napi::Value PEBinary::GetIsPie(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!binary_) return env.Undefined();
  return Napi::Boolean::New(env, binary_->is_pie());
}

Napi::Value PEBinary::GetHasNx(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!binary_) return env.Undefined();
  return Napi::Boolean::New(env, binary_->has_nx());
}

} // namespace node_lief
