# Copyright 2020-2023 Vector 35 Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from binaryninja.settings import Settings

from binaryninja._binaryninjacore import BNGetUserPluginDirectory
user_plugin_dir = os.path.realpath(BNGetUserPluginDirectory())
current_path = os.path.realpath(__file__)

# If BN_STANDALONE_DEBUGGER is set, only initialize the python module when it is loaded from the user plugin dir
if os.environ.get('BN_STANDALONE_DEBUGGER'):
    if current_path.startswith(user_plugin_dir):
        from .debuggercontroller import *
        from .debugadaptertype import *
        from .debugger_enums import *
else:
    if Settings().get_bool('corePlugins.debugger') and (os.environ.get('BN_DISABLE_CORE_DEBUGGER') is None):
        from .debuggercontroller import *
        from .debugadaptertype import *
        from .debugger_enums import *
