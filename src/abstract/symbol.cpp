/* Symbol stub - full implementation in next phase */
#include "symbol.h"

namespace node_lief {

Napi::Object AbstractSymbol::Init(Napi::Env env, Napi::Object exports) {
  Napi::Function constructor = DefineClass(env, "Symbol", {});
  exports.Set("Symbol", constructor);
  return exports;
}

AbstractSymbol::AbstractSymbol(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<AbstractSymbol>(info) {}

} // namespace node_lief
