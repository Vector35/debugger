llvm_version = "19.1.7"
msvc_build = "14.34"
vs_version = "2022"

# Revisions of the Vector35 llvm-build / qt-build recipe repos whose Jenkins artifacts we
# link against. These replace carrying llvm-build / qt-build as git submodules: the dev
# pipeline reads these hashes and copies the upstream build whose GIT_COMMIT matches
# (see Jenkinsfile-dev :: findMatchingBuild). Keep in sync with the binaryninja repo's
# llvm-build / qt-build submodule revisions whenever those are bumped.
llvm_build_commit = "c58025321255bc6ea9b69745985b025290bf6520"
qt_build_commit = "68ec39b2d068e9b85966bc2c12053e22af1b411c"
