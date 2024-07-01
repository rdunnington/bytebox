== Failed Optimizations ==

* Giving locals their own stack space separate from values. The idea here was to save
  some perf on push/pop of call frames so that we wouldn't have to copy the return values
  back to the appropriate place. But since the wasm calling convention is to pass params
  via the stack, you'd have to copy them elsewhere anyway, defeating the point of 
  the optimization anyway, which is to avoid copying values around.

* Instruction stream. Instead of having an array of structs that contain opcode + immediates,
  have a byte stream of opcodes and immediates where you don't have to pay for the extra memory
  of the immediates if you don't need them. But it turns out that a lot of instructions 
  use immediates anyway and the overhead of fetching them out of the stream is more
  expensive than just paying for the cache hits. Overall memory is 
