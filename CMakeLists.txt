cmake_minimum_required(VERSION 3.21)
project(symp VERSION 1.2
			 DESCRIPTION "mach-o symbol patching tool"
			 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# add_compile_options(-Wall -Wshadow -fsanitize=address,undefined)
# add_link_options(-Wall -Wshadow -fsanitize=address,undefined)

add_executable(symp
	src/cli.c
	src/fileio.c
	src/builtin.c
	src/sym/macho.c
	src/sym/search_common.c
	src/sym/symbol.c
	src/sym/objcmeta.c
	src/sym/resolve.c
	src/main.c)

add_custom_command(
	OUTPUT symp.pkg
	COMMAND mkdir -p root
	COMMAND cp symp root
	COMMAND pkgbuild --version 1.2
					 --identifier com.antibiotics.tools
					 --install-location /usr/local/bin
					 --min-os-version 10.13
					 --compression latest
					 --timestamp
					 --root root
					 symp.pkg
	COMMAND rm -r root
	DEPENDS symp
	VERBATIM)

add_custom_target(pkg DEPENDS symp.pkg)

install(TARGETS symp DESTINATION /usr/local/bin)
