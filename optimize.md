# Optimizations

It's useful to document successful optimizations to give reasoning for why the implementation
deviates from the spec, as well as failed optimizations to document why they didn't work.

# Successful

* Splitting the If instruction into 2, the If and IfNoElse opcodes. Splitting up the base If opcode
  into these two cases allows the implementation to avoid an extra branch.

* Keeping separate values and labels in different stacks makes it easy to "return" values from
  a label. In a shared stack environment you'd have to push the label first, then the values would
  be pushed on after. Returning from a block requires the label to be popped, and if it returns
  any values, they still need to reside on the top of the stack. Having the labels share stack
  space with values require would require the values to be copied down to where the label was
  originally.

* Funcref in 8 bytes (single pointer). Normally you woudld store the index of the function and a
  pointer to the module it belongs to. Having a global index of modules is kind of gross, but by
  default import functions don't have a local body so you can't treat them the same. However,
  Bytebox generates function import trampolines at decode time to ensure each import function has
  a corresponding local function. This gives the benefit of allowing funcrefs to always have a
  pointer to a local function that will immediately handle the trampoline logic to the imported
  function, which allows it to fit in 8 bytes in the stack/register.

* Packing bundled immediates into 8 bytes. Bundling opcodes and immediates into a single 
  "instruction" allows for close access to immediates for common opcodes like i32.Const or 
  Local.Set/Get. Getting immediates to be as small as possible, i.e. 8 bytes, is important. Large
  immediates were moved to their own packed array, and the op immediate is used to index this array.
  This should be OK since those ops aren't that common anyway so an extra lookup won't have that 
  large an impact on overall program perf. However, the commonly-used `if` op needs to store the
  number of return values (2 bytes) and block continuations 2x (32 bytes). Normally this would be 
  12 bytes, but by using continuations relative to the location of the instruction, those offsets
  can be compressed into 2 bytes each, resulting in a total size of 6 bytes for all immediates.

* Labeled switch / computed goto. This backend is faster than the tailcall backend, but is harder
  to inspect the assembly for individual ops, which is why we keep the tailcall backend around.
  Build with `zig build asm -Doptimize=ReleaseFast -Dvm_kind=tailcall` and search for
  `op_Local_Get` for an example to see how it's easy to inspect individual function ops.

# Failed Optimizations

* Giving locals their own stack space separate from values. The idea here was to save some perf on
  push/pop of call frames so that we wouldn't have to copy the return values back to the
  appropriate place. But since the wasm calling convention is to pass params via the stack, you'd 
  have to copy them elsewhere anyway, defeating the point of the optimization, which is to avoid
  copying values around.

* Instruction stream. Instead of having an array of structs that contain opcode + immediates, have
  a byte stream of opcodes and immediates where you don't have to pay for the extra memory of the
  immediates if you don't need them. But it turns out that very commmon instructions use
  immediates anyway. Also the inconsistent access patterns probably don't help the CPU memory 
  prefetcher out much. And finally, there is a bit of overhead calculating the exact aligned 
  offsets to fetching them out of the stream, and then advancing the stream pointer by an aligned
  amount.
