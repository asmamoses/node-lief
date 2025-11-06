#pragma once

#include <napi.h>
#include <LIEF/MachO.hpp>

namespace node_lief {

/**
 * Wrapper for LIEF::MachO::SegmentCommand
 * Represents a MachO segment
 */
class Segment : public Napi::ObjectWrap<Segment> {
 public:
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  // Factory method to create from LIEF MachO segment
  static Napi::Object NewInstance(Napi::Env env, LIEF::MachO::SegmentCommand* segment);

  // Get underlying segment
  LIEF::MachO::SegmentCommand* GetSegment() const { return segment_; }

  // Constructor (must be public for ObjectWrap)
  explicit Segment(const Napi::CallbackInfo& info);

 private:
  LIEF::MachO::SegmentCommand* segment_;

  // Properties
  Napi::Value GetName(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualAddress(const Napi::CallbackInfo& info);
  Napi::Value GetVirtualSize(const Napi::CallbackInfo& info);
  Napi::Value GetFileOffset(const Napi::CallbackInfo& info);
  Napi::Value GetFileSize(const Napi::CallbackInfo& info);

  // Methods
  Napi::Value GetSections(const Napi::CallbackInfo& info);
  Napi::Value GetSection(const Napi::CallbackInfo& info);
};

} // namespace node_lief
