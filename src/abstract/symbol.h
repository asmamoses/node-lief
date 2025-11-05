#pragma once

#include <napi.h>

namespace node_lief {

class AbstractSymbol : public Napi::ObjectWrap<AbstractSymbol> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
  explicit AbstractSymbol(const Napi::CallbackInfo& info);

 private:
  // Properties and methods will be implemented in the full version
};

} // namespace node_lief
