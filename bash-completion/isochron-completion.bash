__isochron_subprog_complete() {
	local prog=$1 && shift
	local subprog=$1 && shift
	local prev=$1 && shift
	local cur=$1 && shift
	local words=("$@")

	local helptext="$(${prog} ${subprog} --help 2>&1)"
	local long_opts=()
	local short_opts=()
	local wordlist=""

	while IFS= read -r line; do
		local filepath=false
		local ifname=false
		local long_opt=
		local short_opt=
		local num_args=
		local opts=
		local ifaces=

		opts=${line%%: *}
		kind=${line##*: }
		kind=${kind%% (optional)}
		short_opt=${opts%%|*}
		long_opt=${opts##*|}

		# Don't suggest options that are already there
		if ! [[ " ${words[*]} " =~ " ${short_opt} " ]]; then
			short_opts=( ${short_opts[@]} ${short_opt} )
		fi
		if ! [[ " ${words[*]} " =~ " ${long_opt} " ]]; then
			long_opts=( ${long_opts[@]} ${long_opt} )
		fi

		case ${kind} in
		"Help text"|"Boolean")
			num_args=0
			;;
		"File path")
			filepath=true
			;;
		"Network interface")
			ifname=true
			;;
		*)
			num_args=1
			;;
		esac

		if [ "${prev}" = "${short_opt}" ] ||
		   [ "${prev}" = "${long_opt}" ]; then
			# If the option requires an argument and this is the argument,
			# don't attempt to complete it unless we know how.
			if [ "${num_args}" = 0 ]; then
				continue
			elif [ ${filepath} = true ]; then
				COMPREPLY=( $(compgen -f -- "${cur}") )
				return
			elif [ ${ifname} = true ]; then
				for iface in $(cd /sys/class/net && ls -d */); do
					ifaces="${ifaces} ${iface%%/}"
				done
				COMPREPLY=( $(compgen -W "${ifaces}" -- "${cur}") )
				return
			else
				return
			fi
		fi
	done < <(printf '%s\n' "${helptext}" | grep ': ')

	wordlist="${short_opts[@]} ${long_opts[@]}"

	COMPREPLY=( $(compgen -W "${wordlist}" -- "${cur}") )
}

__isochron_complete() {
	local cur=""
	local prev=""
	local words=()
	local prog=""
	local subprog=""

	_get_comp_words_by_ref -n : cur prev words

	if [ "$(basename ${prev} 2> /dev/null)" = "isochron" ]; then
		COMPREPLY=( $(compgen -W "send rcv report -h --help -v --version" -- "${cur}") )
		return
	fi

	if [ ${#words[*]} -lt 2 ]; then
		return
	fi

	prog="${words[0]}"
	subprog="${words[1]}"

	case "${subprog}" in
	send|rcv|report)
		__isochron_subprog_complete "${prog}" "${subprog}" "${prev}" "${cur}" ${words[@]}
		;;
	*)
		;;
	esac
}

complete -F __isochron_complete isochron
