llvm_version = "22.1.8"
msvc_build = "14.34"
vs_version = "2022"

# Revisions of the Vector35 llvm-build / qt-build recipe repos whose Jenkins artifacts we
# link against. These replace carrying llvm-build / qt-build as git submodules: Jenkinsfile-dev
# reads these hashes and passes them to copyExternalArtifactsEx, which copies the upstream
# build whose commit matches. Keep in sync with the binaryninja repo's llvm-build / qt-build
# submodule revisions whenever those are bumped.
llvm_build_commit = "9f9ae7ed91e0fe04ecf751e21cf23a6186988ccf"
qt_build_commit = "7827581354482275715048965178721420353140"
