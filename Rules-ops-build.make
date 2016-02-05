# Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

.PHONY: ops-ipsecd-test ops-ipsecd-valgrind-test

#Coverage support
MODULE_TEST_TARGET=ops-ipsecd-test
COVERAGE_EXCLUDE_PATTERN+=external* boost* ovs*

UT_BIN=src/ops-ipsecd/build/tests/ops-ipsecd-ut

# Use UT_PARAMS to pass parameters to the test harness. Default value in tools/Rules.make
ops-ipsecd-test:
	$(V) $(call EXECUTE_UT_TEST_HARNESS, $(UT_BIN))

# Use VALGRIND_OPTIONS to modify the options to valgrind. Default value in tools/Rules.make
ops-ipsecd-valgrind-test:
	$(V) $(call EXECUTE_UT_TEST_HARNESS_ON_VALGRIND, $(UT_BIN))
