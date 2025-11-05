/*
 * LIEF Abstract Binary Binding
 *
 * Exposes the generic Binary class which works across all formats (ELF, PE, MachO)
 */

#include "binary.h"
#include "section.h"
#include "../macho/binary.h"
#include <LIEF/LIEF.hpp>
#include <sstream>

namespace node_lief {

// Static storage for constructor (not using instance data to avoid conflicts)
static Napi::FunctionReference* binary_constructor = nullptr;

Napi::Object AbstractBinary::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Binary", {
    // Properties
    InstanceAccessor<&AbstractBinary::GetFormat>("format"),
    InstanceAccessor<&AbstractBinary::GetEntrypoint>("entrypoint"),
    InstanceAccessor<&AbstractBinary::GetIsPie>("isPie"),
    InstanceAccessor<&AbstractBinary::GetHasNx>("hasNx"),
    InstanceAccessor<&AbstractBinary::GetHeader>("header"),

    // Methods
    InstanceMethod<&AbstractBinary::GetSegments>("segments"),
    InstanceMethod<&AbstractBinary::GetSections>("sections"),
    InstanceMethod<&AbstractBinary::GetSymbols>("symbols"),
    InstanceMethod<&AbstractBinary::GetRelocations>("relocations"),
    InstanceMethod<&AbstractBinary::GetSymbol>("getSymbol"),
    InstanceMethod<&AbstractBinary::PatchAddress>("patchAddress"),
    InstanceMethod<&AbstractBinary::Write>("write"),
  });

  // Store constructor in static variable
  binary_constructor = new Napi::FunctionReference();
  *binary_constructor = Napi::Persistent(constructor);

  exports.Set("Binary", constructor);
  return exports;
}

// Helper to create Binary instances from parsed LIEF binaries
Napi::Object AbstractBinary::NewInstance(Napi::Env env, std::unique_ptr<LIEF::Binary> binary) {
  if (!binary_constructor) {
    Napi::Error::New(env, "Binary constructor not initialized").ThrowAsJavaScriptException();
    return Napi::Object::New(env);
  }

  // Create an empty Binary object (constructor will be called but won't parse)
  Napi::Object obj = binary_constructor->New({});

  // Get the C++ wrapper and replace its binary
  AbstractBinary* wrapper = Napi::ObjectWrap<AbstractBinary>::Unwrap(obj);
  wrapper->binary_ = std::move(binary);

  return obj;
}

AbstractBinary::AbstractBinary(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<AbstractBinary>(info), binary_(nullptr) {
  Napi::Env env = info.Env();

  // Allow construction with no args (for NewInstance helper)
  if (info.Length() == 0) {
    return;
  }

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "Binary constructor requires a file path").ThrowAsJavaScriptException();
    return;
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "Binary constructor requires a string file path").ThrowAsJavaScriptException();
    return;
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file
  auto parsed = LIEF::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse binary file").ThrowAsJavaScriptException();
    return;
  }

  binary_ = std::move(parsed);
}

Napi::Value AbstractBinary::GetFormat(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  std::string format_str;
  switch (binary_->format()) {
    case LIEF::Binary::FORMATS::ELF:
      format_str = "ELF";
      break;
    case LIEF::Binary::FORMATS::PE:
      format_str = "PE";
      break;
    case LIEF::Binary::FORMATS::MACHO:
      format_str = "MachO";
      break;
    default:
      format_str = "UNKNOWN";
  }

  return Napi::String::New(env, format_str);
}

Napi::Value AbstractBinary::GetEntrypoint(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  // Return as BigInt for proper 64-bit integer handling
  return Napi::BigInt::New(env, static_cast<uint64_t>(binary_->entrypoint()));
}

Napi::Value AbstractBinary::GetIsPie(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  return Napi::Boolean::New(env, binary_->is_pie());
}

Napi::Value AbstractBinary::GetHasNx(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  return Napi::Boolean::New(env, binary_->has_nx());
}

Napi::Value AbstractBinary::GetHeader(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  auto header = binary_->header();

  // Create a JavaScript object representing the header
  Napi::Object header_obj = Napi::Object::New(env);
  header_obj.Set("architecture", Napi::Number::New(env, static_cast<uint32_t>(header.architecture())));
  header_obj.Set("entrypoint", Napi::BigInt::New(env, header.entrypoint()));
  header_obj.Set("is_32", Napi::Boolean::New(env, header.is_32()));
  header_obj.Set("is_64", Napi::Boolean::New(env, header.is_64()));

  return header_obj;
}

Napi::Value AbstractBinary::GetSections(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  Napi::Array sections_array = Napi::Array::New(env);
  auto sections = binary_->sections();

  uint32_t idx = 0;
  for (auto& section : sections) {
    Napi::Object section_obj = Napi::Object::New(env);
    section_obj.Set("name", Napi::String::New(env, section.name()));
    section_obj.Set("virtual_address", Napi::BigInt::New(env, section.virtual_address()));
    section_obj.Set("size", Napi::BigInt::New(env, section.size()));
    section_obj.Set("offset", Napi::BigInt::New(env, section.offset()));

    sections_array[idx++] = section_obj;
  }

  return sections_array;
}

Napi::Value AbstractBinary::GetSymbols(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  Napi::Array symbols_array = Napi::Array::New(env);
  auto symbols = binary_->symbols();

  uint32_t idx = 0;
  for (auto& symbol : symbols) {
    Napi::Object symbol_obj = Napi::Object::New(env);
    symbol_obj.Set("name", Napi::String::New(env, symbol.name()));
    symbol_obj.Set("value", Napi::BigInt::New(env, symbol.value()));
    symbol_obj.Set("size", Napi::BigInt::New(env, symbol.size()));

    symbols_array[idx++] = symbol_obj;
  }

  return symbols_array;
}

Napi::Value AbstractBinary::GetRelocations(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  Napi::Array relocations_array = Napi::Array::New(env);
  auto relocations = binary_->relocations();

  uint32_t idx = 0;
  for (auto& reloc : relocations) {
    Napi::Object reloc_obj = Napi::Object::New(env);
    reloc_obj.Set("address", Napi::BigInt::New(env, reloc.address()));
    reloc_obj.Set("size", Napi::Number::New(env, reloc.size()));

    relocations_array[idx++] = reloc_obj;
  }

  return relocations_array;
}

Napi::Value AbstractBinary::GetSymbol(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_ || info.Length() < 1 || !info[0].IsString()) {
    return env.Null();
  }

  std::string symbol_name = info[0].As<Napi::String>();
  auto symbol = binary_->get_symbol(symbol_name);

  if (!symbol) {
    return env.Null();
  }

  Napi::Object symbol_obj = Napi::Object::New(env);
  symbol_obj.Set("name", Napi::String::New(env, symbol->name()));
  symbol_obj.Set("value", Napi::BigInt::New(env, symbol->value()));
  symbol_obj.Set("size", Napi::BigInt::New(env, symbol->size()));

  return symbol_obj;
}

Napi::Value AbstractBinary::PatchAddress(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_ || info.Length() < 2) {
    Napi::TypeError::New(env, "patch_address requires address and patch data")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get address (supports both Number and BigInt)
  uint64_t address = 0;
  if (info[0].IsBigInt()) {
    bool lossless = false;
    address = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
  } else if (info[0].IsNumber()) {
    address = static_cast<uint64_t>(info[0].As<Napi::Number>().Uint32Value());
  } else {
    Napi::TypeError::New(env, "Address must be a number or BigInt")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get patch data (as Buffer or Array)
  std::vector<uint8_t> patch;
  if (info[1].IsBuffer()) {
    auto buffer = info[1].As<Napi::Buffer<uint8_t>>();
    patch.assign(buffer.Data(), buffer.Data() + buffer.Length());
  } else if (info[1].IsArray()) {
    auto arr = info[1].As<Napi::Array>();
    for (uint32_t i = 0; i < arr.Length(); i++) {
      auto val = arr.Get(i).As<Napi::Number>();
      patch.push_back(static_cast<uint8_t>(val.Uint32Value()));
    }
  } else {
    Napi::TypeError::New(env, "Patch data must be a Buffer or Array")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  // Apply the patch
  binary_->patch_address(address, patch);

  return env.Undefined();
}

Napi::Value AbstractBinary::GetSegments(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_) {
    return env.Null();
  }

  // Note: Segments are format-specific (ELF has segments, PE has sections)
  // The abstract Binary class doesn't have a segments() method
  // For now, return an empty array. Format-specific bindings should override this.
  Napi::Array segments_array = Napi::Array::New(env);

  return segments_array;
}

Napi::Value AbstractBinary::Write(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (!binary_ || info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "write() requires an output file path")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string output_path = info[0].As<Napi::String>();

  try {
    // Use format-specific builders to write the binary
    switch (binary_->format()) {
      case LIEF::Binary::FORMATS::ELF: {
        auto* elf_bin = dynamic_cast<LIEF::ELF::Binary*>(binary_.get());
        if (elf_bin) {
          LIEF::ELF::Builder builder(*elf_bin);
          builder.build();
          builder.write(output_path);
        } else {
          Napi::Error::New(env, "Failed to cast to ELF::Binary")
              .ThrowAsJavaScriptException();
          return env.Undefined();
        }
        break;
      }
      case LIEF::Binary::FORMATS::PE: {
        auto* pe_bin = dynamic_cast<LIEF::PE::Binary*>(binary_.get());
        if (pe_bin) {
          LIEF::PE::Builder::config_t config;
          LIEF::PE::Builder builder(*pe_bin, config);
          builder.build();
          builder.write(output_path);
        } else {
          Napi::Error::New(env, "Failed to cast to PE::Binary")
              .ThrowAsJavaScriptException();
          return env.Undefined();
        }
        break;
      }
      case LIEF::Binary::FORMATS::MACHO: {
        auto* macho_bin = dynamic_cast<LIEF::MachO::Binary*>(binary_.get());
        if (macho_bin) {
          // Use static write method for MachO
          LIEF::MachO::Builder::write(*macho_bin, output_path);
        } else {
          Napi::Error::New(env, "Failed to cast to MachO::Binary")
              .ThrowAsJavaScriptException();
          return env.Undefined();
        }
        break;
      }
      default:
        Napi::Error::New(env, "Unsupported binary format for writing")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    return env.Undefined();
  } catch (const std::exception& e) {
    Napi::Error::New(env, std::string("Failed to write binary: ") + e.what())
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
}

Napi::Value Parse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "parse() requires a file path string")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string filename = info[0].As<Napi::String>();

  // Parse the binary file
  auto parsed = LIEF::Parser::parse(filename);
  if (!parsed) {
    Napi::Error::New(env, "Failed to parse binary file").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Return the concrete type based on format (matching Python LIEF API)
  auto format = parsed->format();

  if (format == LIEF::Binary::FORMATS::MACHO) {
    // For MachO, parse with format-specific parser to get proper Binary
    auto fat_binary = LIEF::MachO::Parser::parse(filename);
    if (!fat_binary || fat_binary->size() == 0) {
      Napi::Error::New(env, "Failed to parse MachO binary").ThrowAsJavaScriptException();
      return env.Null();
    }
    // Take the first binary from the FatBinary
    auto macho_binary = fat_binary->take(0);
    if (!macho_binary) {
      Napi::Error::New(env, "Failed to extract MachO binary").ThrowAsJavaScriptException();
      return env.Null();
    }
    return MachOBinary::NewInstance(env, std::move(macho_binary));
  }
  // For other formats, return the abstract wrapper for now
  // TODO: Add PE and ELF concrete wrappers
  return AbstractBinary::NewInstance(env, std::move(parsed));
}

} // namespace node_lief
