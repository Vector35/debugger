llvm_version = "22.1.8"
msvc_build = "14.34"
vs_version = "2022"

# Revisions of the Vector35 llvm-build / qt-build recipe repos whose Jenkins artifacts we
# link against. These replace carrying llvm-build / qt-build as git submodules: Jenkinsfile-dev
# reads these hashes and passes them to copyExternalArtifactsEx, which copies the upstream
# build whose commit matches. Keep in sync with the binaryninja repo's llvm-build / qt-build
# submodule revisions whenever those are bumped.
llvm_build_commit = "00399aeba5ae06a456dd5e32a4f5066c347af5d7"
qt_build_commit = "30ebbf347e40b0646f5878fef292c346573a28a1"
