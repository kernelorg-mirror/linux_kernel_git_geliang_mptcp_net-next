#! /bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly KSFT_FAIL=1
readonly KSFT_SKIP=4

mptcp_lib_expect_all_features() {
	[ "${SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES:-}" = "1" ]
}

# $1: msg
mptcp_lib_fail_if_expected_feature() {
	if mptcp_lib_expect_all_features; then
		echo "ERROR: missing feature: ${*}"
		exit ${KSFT_FAIL}
	fi
}

# $1: file
mptcp_lib_has_file() {
	local f="${1}"

	if [ ! -f "${f}" ]; then
		mptcp_lib_fail_if_expected_feature "${f} file not found"

		return 1
	fi
}

mptcp_lib_check_mptcp() {
	if ! mptcp_lib_has_file "/proc/sys/net/mptcp/enabled"; then
		echo "SKIP: MPTCP support is not available"
		exit ${KSFT_SKIP}
	fi
}

mptcp_lib_check_kallsyms() {
	if ! mptcp_lib_has_file "/proc/kallsyms"; then
		echo "SKIP: CONFIG_KALLSYMS is missing"
		exit ${KSFT_SKIP}
	fi
}

# $1: part of a symbol to look at, add '$' at the end for full name
mptcp_lib_kallsyms_has() {
	local sym="${1}"

	mptcp_lib_check_kallsyms

	if ! grep -q " ${sym}" /proc/kallsyms; then
		# We want our CI to complain if a symbol has not been found
		mptcp_lib_fail_if_expected_feature "${sym} symbol not found"

		return 1
	fi
}

# !!!AVOID USING THIS!!!
# Features might not land in the expected version and features can be backported
#
# $1: kernel version, e.g. 6.3
mptcp_lib_kversion_lower_than() {
	local exp_maj="${1%.*}"
	local exp_min="${1#*.}"
	local v maj min

	v=$(uname -r | cut -d'.' -f1,2)
	maj=${v%.*}
	min=${v#*.}

	[ "${maj}" -lt "${exp_maj}" ] ||
		{ [ "${maj}" -eq "${exp_maj}" ] && [ "${min}" -lt "${exp_min}" ]; }
}
