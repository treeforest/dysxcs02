// Package sdf 提供 GM/T 0018-2012 密码设备函数（SDF）的惯用 Go 绑定。
//
// 本包以 [include/libsdf.h] 为 API 契约，封装 libsdf.so 全部 SDF_API 导出函数。
// 核心资源类型为 Device、Session、KeyHandle；方法返回 (result, error)。
//
// Session 及依赖会话状态的杂凑流（HashInit 等）非线程安全，
// 并发场景请为每个 goroutine 使用独立 Session。
//
// [include/libsdf.h]: ../include/libsdf.h
package sdf
