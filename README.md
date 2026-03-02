## Config

Ensure that `snark_lib` python module is available in your python path.

## Notes 

Writing programs is similar to cairo. Programming with the python dsl requires you to manipulate memory cells directly.
[TEMP] `leanvm` does not support zk for now. 

Copied from `zkDSL.md`, in lean repo

1. Use unroll for small, fixed-size loops
2. Use const parameters when loop bounds depend on arguments
3. Use mut sparingly - immutable is easier to verify
4. Use x: Imu or x: Mut for forward-declaring variables that will be assigned in branches
5. Match patterns must be consecutive integers (can start from any value)

### Documentation (`zkDSL.md`)

- No `bool`?
- No ability to do `address[-1]`

