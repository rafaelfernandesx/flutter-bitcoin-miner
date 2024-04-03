#ifndef FFI_TEST_EXAMPLE_H
#define FFI_TEST_EXAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default")))
char* minerHeader(const char* headerHex, const char* targetHex);

#ifdef __cplusplus
}
#endif

#endif //FFI_TEST_EXAMPLE_H
