How to Contribute
=================

Anyone is welcome to contribute through the official repository
on github:

```
git clone -b dev https://github.com/ntop/ntopng.git
```

If you want to contribute with a patch, the first step to get it
in the main tree is to run the regression tests included in the 
ntopng source code. 


Create a PR
===========

Please check the official GitHub documentation for instructions
for sending Pull Requests:

https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request

After the submission the ntop core team will review the patches to
make sure they are well written and do the right things. If everything
goes well, patches are applied to the dev branch and will be included
in the nightly builds.


Memory Leak Detection
=====================

It is recommended to also enable the runtime memory leak detector
based on the clang sanitizer when running the tests. This would
check both memory errors and leaks (with no performance overhead). 

In order to enable the sanitizer, please compile ntopng as below.

```
cd ntopng
./autogen.sh
./configure --with-sanitizer
make
```

This will report at the end of each test any memory leak or bad
memory access, if any.
