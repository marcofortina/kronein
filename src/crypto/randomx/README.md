# Vendored RandomX

This directory vendors the RandomX reference implementation at release
**v2.0.1**, commit `aaafe71322df6602c21a5c72937ac284724ae561`.

Upstream: <https://github.com/tevador/RandomX>

The upstream source and its BSD 3-Clause license are retained under
`upstream/`. Kronein carries these integration-only patches:

- tests and installation can be disabled in the upstream `CMakeLists.txt`
  when RandomX is built as an internal dependency;
- the CMake policy baseline is 3.10, avoiding deprecated compatibility modes
  under the project's strict CI configuration;
- documentation links for files omitted from the vendored subset point to the
  corresponding v2.0.1 upstream files;
- the x86 static assembly declares a non-executable GNU stack on ELF targets.

Algorithm and API sources are unchanged.

Kronein's C++ ownership, cache reuse, v2 flag selection, and full/light mode
adapter live in `src/crypto/randomx.{h,cpp}` outside this directory.
