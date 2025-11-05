/*
 * LIEF PE Binary Binding
 *
 * Provides PE-specific binary manipulation for Windows executables
 */

#include "binary.h"
#include "../abstract/section.h"

namespace node_lief {

Napi::Object PEBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    InstanceMethod<&PEBinary::GetSection>("get_section"),
    InstanceMethod<&PEBinary::Write>("write"),
  });

  Napi::FunctionReference* constructor_ref = new Napi::FunctionReference();
  *constructor_ref = Napi::Persistent(constructor);
  env.SetInstanceData(constructor_ref);

  exports.Set("Binary", constructor);
  return exports;
}

PEBinary::PEBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<PEBinary>(info), binary_(nullptr) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "PEBinary constructor requires a file path").ThrowAsJavaScriptException();
    return;
  }

  if (!info[0].IsString()) {
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

} // namespace node_lief
