# Development

This document describes how to build and test Memento.

Memento development is ongoing on Ubuntu 12.04, so the processes described
below are targetted for (and tested on) this platform.  The code has been
written to be portable, though, and should compile on other platforms once the
required dependencies are installed.

Memento is integrated into the Application Server framework provided by Sprout,
and can be run on the Sprout nodes or as a standalone node.

## Building the code

Memento is integrated with Sprout, and is built as part of the Sprout [build](https://github.com/Metaswitch/sprout/blob/dev/docs/Development.md).

## Getting the Code

The Memento code is all in the `memento` repository, and its submodules, which
are in the `modules` subdirectory.

To get all the code, clone the memento repository with the `--recursive` flag to
indicate that submodules should be cloned too.

    git clone --recursive git@github.com:Metaswitch/memento.git

This accesses the repository over SSH on Github, and will not work unless you have a Github account and registered SSH key. If you do not have both of these, you will need to configure Git to read over HTTPS instead:

    git config --global url."https://github.com/".insteadOf git@github.com:
    git clone --recursive git@github.com:Metaswitch/memento.git

## Building Binaries

Note that the first build can take a long time. It takes 10-15 minutes on
an EC2 m1.small instance.

To build the memento code only and all its dependencies, change to the top-level `memento`
directory and issue `make`.

On completion,

* the memento binary is in `build/bin`
* libraries on which it depends are in `usr/lib`.

Subsequent builds should be quicker, but still check all of the
dependencies. For fast builds when you've only changed memento code, change to
the `src` subdirectory below the top-level `memento` directory and then run
`make`.

## Running Unit Tests

To run the memento unit test suite, change to the `src` subdirectory below
the top-level `memento` directory and issue `make test`.

Memento unit tests use the [Google Test](https://code.google.com/p/googletest/)
framework, so the output from the test run looks something like this.

    [==========] Running 58 tests from 9 test cases.
    [----------] Global test environment set-up.
	...
        [----------] 3 tests from CallListStoreProcessorTest
        [ RUN      ] CallListStoreProcessorTest.CallListIsCountNeededNoLimit
        [       OK ] CallListStoreProcessorTest.CallListIsCountNeededNoLimit (0 ms)
        [ RUN      ] CallListStoreProcessorTest.CallListWrite
        [       OK ] CallListStoreProcessorTest.CallListWrite (1001 ms)
        [ RUN      ] CallListStoreProcessorTest.CallListWriteWithError
        [       OK ] CallListStoreProcessorTest.CallListWriteWithError (1000 ms)
        [----------] 3 tests from CallListStoreProcessorTest (2002 ms total)
	...
    [----------] Global test environment tear-down
    [==========] 58 tests from 9 test cases ran. (27347 ms total)
    [  PASSED  ] 58 tests.

`make test` also automatically runs code coverage (using
[gcov](http://gcc.gnu.org/onlinedocs/gcc/Gcov.html)) and memory leak checks
(using [Valgrind](http://valgrind.org/)).  If code coverage decreases or
memory is leaked during the tests, an error is displayed. To see the detailed
code coverage results, run `make coverage_raw`.

The memento makefile offers the following additional options and targets.

*   `make run_test` just runs the tests without doing code coverage or memory
    leak checks.
*   Passing `JUSTTEST=testname` just runs the specified test case.
*   Passing `NOISY=T` enables verbose logging during the tests; you can add
    a logging level (e.g., `NOISY=T:99`) to control which logs you see.
*   `make debug` runs the tests under gdb.
*   `make vg_raw` just runs the memory leak checks.
