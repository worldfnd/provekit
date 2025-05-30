// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") b[0], in("x5") b[1], in("x6") b[2], in("x7") b[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _,
// lateout("lr") _
  mul x8, x0, x4
  umulh x9, x0, x4
  mul x10, x1, x4
  umulh x11, x1, x4
  adds x9, x10, x9
  cinc x10, x11, hs
  mul x11, x2, x4
  umulh x12, x2, x4
  adds x10, x11, x10
  cinc x11, x12, hs
  mul x12, x3, x4
  umulh x4, x3, x4
  adds x11, x12, x11
  cinc x4, x4, hs
  mul x12, x0, x5
  umulh x13, x0, x5
  adds x9, x12, x9
  cinc x12, x13, hs
  mul x13, x1, x5
  umulh x14, x1, x5
  adds x12, x13, x12
  cinc x13, x14, hs
  adds x10, x12, x10
  cinc x12, x13, hs
  mul x13, x2, x5
  umulh x14, x2, x5
  adds x12, x13, x12
  cinc x13, x14, hs
  adds x11, x12, x11
  cinc x12, x13, hs
  mul x13, x3, x5
  umulh x5, x3, x5
  adds x12, x13, x12
  cinc x5, x5, hs
  adds x4, x12, x4
  cinc x5, x5, hs
  mul x12, x0, x6
  umulh x13, x0, x6
  adds x10, x12, x10
  cinc x12, x13, hs
  mul x13, x1, x6
  umulh x14, x1, x6
  adds x12, x13, x12
  cinc x13, x14, hs
  adds x11, x12, x11
  cinc x12, x13, hs
  mul x13, x2, x6
  umulh x14, x2, x6
  adds x12, x13, x12
  cinc x13, x14, hs
  adds x4, x12, x4
  cinc x12, x13, hs
  mul x13, x3, x6
  umulh x6, x3, x6
  adds x12, x13, x12
  cinc x6, x6, hs
  adds x5, x12, x5
  cinc x6, x6, hs
  mul x12, x0, x7
  umulh x0, x0, x7
  adds x11, x12, x11
  cinc x0, x0, hs
  mul x12, x1, x7
  umulh x1, x1, x7
  adds x0, x12, x0
  cinc x1, x1, hs
  adds x0, x0, x4
  cinc x1, x1, hs
  mul x4, x2, x7
  umulh x2, x2, x7
  adds x1, x4, x1
  cinc x2, x2, hs
  adds x1, x1, x5
  cinc x2, x2, hs
  mul x4, x3, x7
  umulh x3, x3, x7
  adds x2, x4, x2
  cinc x3, x3, hs
  adds x2, x2, x6
  cinc x3, x3, hs
  mov x4, #56431
  movk x4, #30457, lsl 16
  movk x4, #30012, lsl 32
  movk x4, #6382, lsl 48
  mov x5, #59151
  movk x5, #41769, lsl 16
  movk x5, #32276, lsl 32
  movk x5, #21677, lsl 48
  mov x6, #34015
  movk x6, #20342, lsl 16
  movk x6, #13935, lsl 32
  movk x6, #11030, lsl 48
  mov x7, #13689
  movk x7, #8159, lsl 16
  movk x7, #215, lsl 32
  movk x7, #4913, lsl 48
  mul x12, x4, x8
  umulh x13, x4, x8
  adds x10, x12, x10
  cinc x12, x13, hs
  mul x13, x5, x8
  umulh x14, x5, x8
  adds x12, x13, x12
  cinc x13, x14, hs
  adds x11, x12, x11
  cinc x12, x13, hs
  mul x13, x6, x8
  umulh x14, x6, x8
  adds x12, x13, x12
  cinc x13, x14, hs
  adds x0, x12, x0
  cinc x12, x13, hs
  mul x13, x7, x8
  umulh x8, x7, x8
  adds x12, x13, x12
  cinc x8, x8, hs
  adds x1, x12, x1
  cinc x8, x8, hs
  adds x2, x2, x8
  cinc x3, x3, hs
  mul x8, x4, x9
  umulh x4, x4, x9
  adds x8, x8, x11
  cinc x4, x4, hs
  mul x11, x5, x9
  umulh x5, x5, x9
  adds x4, x11, x4
  cinc x5, x5, hs
  adds x0, x4, x0
  cinc x4, x5, hs
  mul x5, x6, x9
  umulh x6, x6, x9
  adds x4, x5, x4
  cinc x5, x6, hs
  adds x1, x4, x1
  cinc x4, x5, hs
  mul x5, x7, x9
  umulh x6, x7, x9
  adds x4, x5, x4
  cinc x5, x6, hs
  adds x2, x4, x2
  cinc x4, x5, hs
  add x3, x3, x4
  mov x4, #61005
  movk x4, #58262, lsl 16
  movk x4, #32851, lsl 32
  movk x4, #11582, lsl 48
  mov x5, #37581
  movk x5, #43836, lsl 16
  movk x5, #36286, lsl 32
  movk x5, #51783, lsl 48
  mov x6, #10899
  movk x6, #30709, lsl 16
  movk x6, #61551, lsl 32
  movk x6, #45784, lsl 48
  mov x7, #36612
  movk x7, #63402, lsl 16
  movk x7, #47623, lsl 32
  movk x7, #9430, lsl 48
  mul x9, x4, x10
  umulh x4, x4, x10
  adds x8, x9, x8
  cinc x4, x4, hs
  mul x9, x5, x10
  umulh x5, x5, x10
  adds x4, x9, x4
  cinc x5, x5, hs
  adds x0, x4, x0
  cinc x4, x5, hs
  mul x5, x6, x10
  umulh x6, x6, x10
  adds x4, x5, x4
  cinc x5, x6, hs
  adds x1, x4, x1
  cinc x4, x5, hs
  mul x5, x7, x10
  umulh x6, x7, x10
  adds x4, x5, x4
  cinc x5, x6, hs
  adds x2, x4, x2
  cinc x4, x5, hs
  add x3, x3, x4
  mov x4, #65535
  movk x4, #61439, lsl 16
  movk x4, #62867, lsl 32
  movk x4, #49889, lsl 48
  mul x4, x4, x8
  mov x5, #1
  movk x5, #61440, lsl 16
  movk x5, #62867, lsl 32
  movk x5, #17377, lsl 48
  mov x6, #28817
  movk x6, #31161, lsl 16
  movk x6, #59464, lsl 32
  movk x6, #10291, lsl 48
  mov x7, #22621
  movk x7, #33153, lsl 16
  movk x7, #17846, lsl 32
  movk x7, #47184, lsl 48
  mov x9, #41001
  movk x9, #57649, lsl 16
  movk x9, #20082, lsl 32
  movk x9, #12388, lsl 48
  mul x10, x5, x4
  umulh x5, x5, x4
  cmn x10, x8
  cinc x5, x5, hs
  mul x8, x6, x4
  umulh x6, x6, x4
  adds x5, x8, x5
  cinc x6, x6, hs
  adds x0, x5, x0
  cinc x5, x6, hs
  mul x6, x7, x4
  umulh x7, x7, x4
  adds x5, x6, x5
  cinc x6, x7, hs
  adds x1, x5, x1
  cinc x5, x6, hs
  mul x6, x9, x4
  umulh x4, x9, x4
  adds x5, x6, x5
  cinc x4, x4, hs
  adds x2, x5, x2
  cinc x4, x4, hs
  add x3, x3, x4
