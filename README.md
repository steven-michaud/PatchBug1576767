# PatchBug1576767

PatchBug1576767 is a macOS kernel extension that is a temporary
workaround for most of the crashes reported at
[Mozilla bug 1576767](https://bugzilla.mozilla.org/show_bug.cgi?id=1576767).
It's also proof, for users who experience these crashes, that they're
caused by an Apple bug. PatchBug1576767 requires macOS Catalina, minor
version 10.15.4 or higher. It only has any effect if you're running
AMD Radeon graphics hardware (since the bug is in Apple's kernel
extension drivers for this hardware).

Building PatchBug1576767 requires XCode and its command line tools. If
you have an Apple developer account, you can get them at
https://developer.apple.com/download/more/. Installing PatchBug1576767
requires an admin account. You also need to turn off at least part of
Apple's System Integrity Protection (SIP), and add "keepsyms=1" to
your kernel boot args.

Here are brief instructions for building and installing
PatchBug1576767:

The easiest way to build PatchBug1576767 is to run `xcodebuild` from
the source distribution's `PatchBug1576767/PatchBug1576767`
directory. Doing this drops a release build into the project's
`build/Release` directory. You should then copy `PatchBug1576767.kext`
to a directory that only `root` has write permissions on, such as
`/usr/local/sbin`:

        sudo cp -R PatchBug1576767.kext /usr/local/sbin

Next you need to completely disable SIP (possibly only temporarily),
by doing the following:

* Boot into your Recovery partition by restarting your computer and
  pressing `Command-R` immediately after you hear the Mac startup
  sound. Release these keys when you see the Apple logo.

* Choose Utilties : Terminal, then do the following at the command
  line:

        csrutil disable

* Quit Terminal and reboot your computer.

Now you can change your kernel boot args (an operation that isn't
permitted while SIP is on). Do the following command in a Terminal
window to see what kernel boot args you already have, if any:

        nvram boot-args

Then run something like the following command:

        sudo nvram boot-args="[oldbootargs] keepsyms=1"

Now you may wish to partially restore System Integrity Protection. You
mustn't turn it back on completely, because that will prevent you from
being able to load `PatchBug1576767.kext`.

Boot into your Recovery partition as above, run Terminal, then run the
following command. You will see a warning from Apple that this isn't a
supported configuration. Nonetheless, it has worked for many years.

        csrutil enable --without kext

Now quit Terminal and reboot your computer.

Now you should be able to load `PatchBug1576767.kext`. But first run
the Console app and filter on messages containing "PatchBug1576767" or
just the word "patch". This is the only way to see the messages that
`PatchBug1576767.kext` displays while running. And thanks to an Apple
design flaw, you'll need to load it twice to see any of its messages:

        sudo kextutil /usr/local/sbin/PatchBug1576767.kext
        sudo kextunload -b org.smichaud.PatchBug1576767
        sudo kextutil /usr/local/sbin/PatchBug1576767.kext

Among other messages, you should see the following two, or ones very
much like them:

        PatchBug1576767: patch_bad_instructions(): AMDRadeonX4000_AMDHWVMContext::mapVA() patched
        PatchBug1576767: patch_bad_instructions(): AMDRadeonX4000_AMDHWVMContext::unmapVA() patched

To unload `PatchBug1576767.kext` and restore Apple's code to its
original (unpatched) condition, do the following:

        sudo kextunload -b org.smichaud.PatchBug1576767

The bug that PatchBug1576767 fixes is as follows. Here is
reconstructed C++ code for two methods in the AMDRadeonX4000 kernel
extension (or AMDRadeonX5000 or AMDRadeonX6000):

        bool AMDRadeonX4000_AMDHWVMContext::mapVA(vm_address_t startAddress, IOAccelMemory* arg2,
                                                  vm_size_t arg3, vm_size_t length,
                                                  AMDRadeonX4000_IAMDHWVMM::VmMapFlags arg5)
        {
          if (startAddress < vmRangeStart) {
            return false;
          }
          if (startAddress + length >= vmRangeEnd) {
            return false;
          }
          ...
        }

        bool AMDRadeonX4000_AMDHWVMContext::unmapVA(vm_address_t startAddress, vm_size_t length)
        {
          if (startAddress < vmRangeStart) {
            return false;
          }
          if (startAddress + length >= vmRangeEnd) {
            return false;
          }
          ...
        }

The bug is in the fourth line of each method:

        if (startAddress + length >= vmRangeEnd) {

should be

        if (startAddress + length > vmRangeEnd) {

The crashes reported at
[Mozilla bug 1576767](https://bugzilla.mozilla.org/show_bug.cgi?id=1576767)
happen when `mapVA()` tries to map in an object which has been
allocated flush up to the end of "vmRange". There's enough space to
map in the object, but the ">=" causes an unexpected failure, which
causes a cascade of other errors, eventually leading to a crash.
