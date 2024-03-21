import subprocess

subprocess.run([
	"python3",
	"test/wasi/wasi-testsuite/test-runner/wasi_test_runner.py",
	"-r",
	"test/wasi/bytebox_adapter.py",
	"-t",
	"./test/wasi/wasi-testsuite/tests/assemblyscript/testsuite/",
	"./test/wasi/wasi-testsuite/tests/c/testsuite/",
	"./test/wasi/wasi-testsuite/tests/rust/testsuite/"])

# the wasi tests leave a bunch of untracked files around after a test run
subprocess.run(["git", "clean", "-f"], cwd="test/wasi/wasi-testsuite")
