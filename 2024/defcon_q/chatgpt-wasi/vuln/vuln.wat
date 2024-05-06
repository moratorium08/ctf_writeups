(module
  (import "env" "print_number" (func $print_number (param i32)))
  (import "env" "check_variable" (func $check_variable (param i32 i32 i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) ))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32) ))

  (memory 0)
  (export "memory" (memory 0))

  ;;(data (i32.const 1024) "hello world")
  ;; (data (i32.const 1036) "\00\04\00\00\0B\00\00\00")


  (func $_start
  (local $value i32)
  ;;(i32.store offset=0x100d151 (i32.const 0) (i32.const 0x1007f4b))
  ;;(i32.store offset=0x100d1e9 (i32.const 0) (i32.const 0x1007f4b))
  ;;(i32.store offset=0x100d1f9 (i32.const 0) (i32.const 0x1007f4b))
  ;;(i32.store offset=0x100d1f1 (i32.const 0) (i32.const 0x1007f4b))
  ;;(i32.store offset=0x100d3c1 (i32.const 0) (i32.const 0x1007f4b))
  ;;(i32.store offset=0x100d3c1 (i32.const 0) (i32.const 0x1007f4b))
  ;;(i32.store offset=0x100d031 (i32.const 0) (i32.const 0x1007f4b))
  (i32.store offset=0x100d151 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100d1e9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100d1f9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100d1f1 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100d3c1 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100d3c1 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100d031 (i32.const 0) (i32.const 0xdeadbeef))

  (i32.store offset=0x100c031 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c151 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c1e9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c1f1(i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c1f9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c4f9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c5b9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c5f9 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c639 (i32.const 0) (i32.const 0xdeadbeef))
  (i32.store offset=0x100c3c1 (i32.const 0) (i32.const 0xdeadbeef))

  (local.set $value (i32.load offset=0x1000001 (i32.const 0)))
  (call $print_number (local.get $value))
  ;;(call $print_number (local.get $value2))
  ;;(call $print_number (local.get $value2))
  ;;(call $print_number (local.get $value2))

    (call $print_number (i32.const 0xdeadbeef))
    (call $check_variable (i32.const 10)(i32.const 10)(i32.const 10))

    (call $fd_write (i32.const 1) (i32.const 0x100c000) (i32.const 1) (i32.const 0x100c000))
    (call $proc_exit (local.get $value))
  )

  (export "_start" (func $_start))
)
