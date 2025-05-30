// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") a1[0], in("x5") a1[1], in("x6") a1[2], in("x7") a1[3],
// in("v0") av[0], in("v1") av[1], in("v2") av[2], in("v3") av[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("x4") out1[0], lateout("x5") out1[1], lateout("x6") out1[2], lateout("x7") out1[3],
// lateout("v0") outv[0], lateout("v1") outv[1], lateout("v2") outv[2], lateout("v3") outv[3],
// lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _, lateout("x20") _, lateout("x21") _, lateout("x22") _, lateout("x23") _, lateout("x24") _, lateout("v4") _, lateout("v5") _, lateout("v6") _, lateout("v7") _, lateout("v8") _, lateout("v9") _, lateout("v10") _, lateout("v11") _, lateout("v12") _, lateout("v13") _, lateout("v14") _, lateout("v15") _, lateout("v16") _, lateout("v17") _, lateout("v18") _, lateout("v19") _,
// lateout("lr") _
  mov x8, #4503599627370495
  mul x9, x0, x0
  dup.2d v4, x8
  mov x10, #5075556780046548992
  umulh x11, x0, x0
  dup.2d v5, x10
  mul x10, x0, x1
  mov x12, #1
  movk x12, #18032, lsl 48
  umulh x13, x0, x1
  dup.2d v6, x12
  adds x11, x10, x11
  cinc x12, x13, hs
  shl.2d v7, v1, #14
  shl.2d v8, v2, #26
  mul x14, x0, x2
  shl.2d v9, v3, #38
  umulh x15, x0, x2
  ushr.2d v3, v3, #14
  shl.2d v10, v0, #2
  adds x12, x14, x12
  cinc x16, x15, hs
  usra.2d v7, v0, #50
  usra.2d v8, v1, #38
  mul x17, x0, x3
  usra.2d v9, v2, #26
  umulh x0, x0, x3
  and.16b v0, v10, v4
  and.16b v1, v7, v4
  adds x16, x17, x16
  cinc x20, x0, hs
  and.16b v2, v8, v4
  adds x10, x10, x11
  cinc x11, x13, hs
  and.16b v7, v9, v4
  mov x13, #13605374474286268416
  mul x21, x1, x1
  dup.2d v8, x13
  umulh x13, x1, x1
  mov x22, #6440147467139809280
  dup.2d v9, x22
  adds x11, x21, x11
  cinc x13, x13, hs
  mov x21, #3688448094816436224
  adds x11, x11, x12
  cinc x12, x13, hs
  dup.2d v10, x21
  mov x13, #9209861237972664320
  mul x21, x1, x2
  dup.2d v11, x13
  mov x13, #12218265789056155648
  umulh x22, x1, x2
  dup.2d v12, x13
  adds x12, x21, x12
  cinc x13, x22, hs
  mov x23, #17739678932212383744
  dup.2d v13, x23
  adds x12, x12, x16
  cinc x13, x13, hs
  mov x16, #2301339409586323456
  mul x23, x1, x3
  dup.2d v14, x16
  mov x16, #7822752552742551552
  umulh x1, x1, x3
  dup.2d v15, x16
  adds x13, x23, x13
  cinc x16, x1, hs
  mov x24, #5071053180419178496
  dup.2d v16, x24
  adds x13, x13, x20
  cinc x16, x16, hs
  mov x20, #16352570246982270976
  adds x11, x14, x11
  cinc x14, x15, hs
  dup.2d v17, x20
  ucvtf.2d v0, v0
  adds x14, x21, x14
  cinc x15, x22, hs
  ucvtf.2d v1, v1
  ucvtf.2d v2, v2
  adds x12, x14, x12
  cinc x14, x15, hs
  ucvtf.2d v7, v7
  mul x15, x2, x2
  ucvtf.2d v3, v3
  mov.16b v18, v5
  umulh x20, x2, x2
  fmla.2d v18, v0, v0
  adds x14, x15, x14
  cinc x15, x20, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v0
  adds x13, x14, x13
  cinc x14, x15, hs
  add.2d v10, v10, v18
  mul x15, x2, x3
  add.2d v8, v8, v19
  mov.16b v18, v5
  umulh x2, x2, x3
  fmla.2d v18, v0, v1
  fsub.2d v19, v6, v18
  adds x14, x15, x14
  cinc x20, x2, hs
  fmla.2d v19, v0, v1
  adds x14, x14, x16
  cinc x16, x20, hs
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  adds x12, x17, x12
  cinc x0, x0, hs
  add.2d v12, v12, v18
  adds x0, x23, x0
  cinc x1, x1, hs
  add.2d v10, v10, v19
  mov.16b v18, v5
  adds x0, x0, x13
  cinc x1, x1, hs
  fmla.2d v18, v0, v2
  adds x1, x15, x1
  cinc x2, x2, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v2
  adds x1, x1, x14
  cinc x2, x2, hs
  add.2d v18, v18, v18
  mul x13, x3, x3
  add.2d v19, v19, v19
  add.2d v14, v14, v18
  umulh x3, x3, x3
  add.2d v12, v12, v19
  mov.16b v18, v5
  adds x2, x13, x2
  cinc x3, x3, hs
  fmla.2d v18, v0, v7
  adds x2, x2, x16
  cinc x3, x3, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v7
  mov x13, #56431
  add.2d v18, v18, v18
  movk x13, #30457, lsl 16
  add.2d v19, v19, v19
  add.2d v16, v16, v18
  movk x13, #30012, lsl 32
  add.2d v14, v14, v19
  movk x13, #6382, lsl 48
  mov.16b v18, v5
  fmla.2d v18, v0, v3
  mov x14, #59151
  fsub.2d v19, v6, v18
  movk x14, #41769, lsl 16
  fmla.2d v19, v0, v3
  add.2d v0, v18, v18
  movk x14, #32276, lsl 32
  add.2d v18, v19, v19
  add.2d v0, v17, v0
  movk x14, #21677, lsl 48
  add.2d v16, v16, v18
  mov x15, #34015
  mov.16b v17, v5
  fmla.2d v17, v1, v1
  movk x15, #20342, lsl 16
  fsub.2d v18, v6, v17
  movk x15, #13935, lsl 32
  fmla.2d v18, v1, v1
  add.2d v14, v14, v17
  movk x15, #11030, lsl 48
  add.2d v12, v12, v18
  mov x16, #13689
  mov.16b v17, v5
  fmla.2d v17, v1, v2
  movk x16, #8159, lsl 16
  fsub.2d v18, v6, v17
  movk x16, #215, lsl 32
  fmla.2d v18, v1, v2
  add.2d v17, v17, v17
  movk x16, #4913, lsl 48
  add.2d v18, v18, v18
  add.2d v16, v16, v17
  mul x17, x13, x9
  add.2d v14, v14, v18
  umulh x20, x13, x9
  mov.16b v17, v5
  fmla.2d v17, v1, v7
  adds x11, x17, x11
  cinc x17, x20, hs
  fsub.2d v18, v6, v17
  mul x20, x14, x9
  fmla.2d v18, v1, v7
  add.2d v17, v17, v17
  umulh x21, x14, x9
  add.2d v18, v18, v18
  adds x17, x20, x17
  cinc x20, x21, hs
  add.2d v0, v0, v17
  add.2d v16, v16, v18
  adds x12, x17, x12
  cinc x17, x20, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v3
  mul x20, x15, x9
  fsub.2d v18, v6, v17
  umulh x21, x15, x9
  fmla.2d v18, v1, v3
  add.2d v1, v17, v17
  adds x17, x20, x17
  cinc x20, x21, hs
  add.2d v17, v18, v18
  adds x0, x17, x0
  cinc x17, x20, hs
  add.2d v1, v15, v1
  add.2d v0, v0, v17
  mul x20, x16, x9
  mov.16b v15, v5
  umulh x9, x16, x9
  fmla.2d v15, v2, v2
  fsub.2d v17, v6, v15
  adds x17, x20, x17
  cinc x9, x9, hs
  fmla.2d v17, v2, v2
  adds x1, x17, x1
  cinc x9, x9, hs
  add.2d v0, v0, v15
  add.2d v15, v16, v17
  adds x2, x2, x9
  cinc x3, x3, hs
  mov.16b v16, v5
  fmla.2d v16, v2, v7
  mul x9, x13, x10
  fsub.2d v17, v6, v16
  umulh x13, x13, x10
  fmla.2d v17, v2, v7
  add.2d v16, v16, v16
  adds x9, x9, x12
  cinc x12, x13, hs
  add.2d v17, v17, v17
  mul x13, x14, x10
  add.2d v1, v1, v16
  add.2d v0, v0, v17
  umulh x14, x14, x10
  mov.16b v16, v5
  adds x12, x13, x12
  cinc x13, x14, hs
  fmla.2d v16, v2, v3
  fsub.2d v17, v6, v16
  adds x0, x12, x0
  cinc x12, x13, hs
  fmla.2d v17, v2, v3
  mul x13, x15, x10
  add.2d v2, v16, v16
  add.2d v16, v17, v17
  umulh x14, x15, x10
  add.2d v2, v13, v2
  add.2d v1, v1, v16
  adds x12, x13, x12
  cinc x13, x14, hs
  mov.16b v13, v5
  adds x1, x12, x1
  cinc x12, x13, hs
  fmla.2d v13, v7, v7
  fsub.2d v16, v6, v13
  mul x13, x16, x10
  fmla.2d v16, v7, v7
  umulh x10, x16, x10
  add.2d v2, v2, v13
  add.2d v1, v1, v16
  adds x12, x13, x12
  cinc x10, x10, hs
  mov.16b v13, v5
  adds x2, x12, x2
  cinc x10, x10, hs
  fmla.2d v13, v7, v3
  fsub.2d v16, v6, v13
  add x3, x3, x10
  fmla.2d v16, v7, v3
  mov x10, #61005
  add.2d v7, v13, v13
  add.2d v13, v16, v16
  movk x10, #58262, lsl 16
  add.2d v7, v11, v7
  add.2d v2, v2, v13
  movk x10, #32851, lsl 32
  mov.16b v11, v5
  movk x10, #11582, lsl 48
  fmla.2d v11, v3, v3
  fsub.2d v13, v6, v11
  mov x12, #37581
  fmla.2d v13, v3, v3
  movk x12, #43836, lsl 16
  add.2d v3, v9, v11
  add.2d v7, v7, v13
  movk x12, #36286, lsl 32
  usra.2d v10, v8, #52
  movk x12, #51783, lsl 48
  usra.2d v12, v10, #52
  usra.2d v14, v12, #52
  mov x13, #10899
  usra.2d v15, v14, #52
  and.16b v8, v8, v4
  movk x13, #30709, lsl 16
  and.16b v9, v10, v4
  movk x13, #61551, lsl 32
  and.16b v10, v12, v4
  and.16b v4, v14, v4
  movk x13, #45784, lsl 48
  ucvtf.2d v8, v8
  mov x14, #36612
  mov x15, #37864
  movk x15, #1815, lsl 16
  movk x14, #63402, lsl 16
  movk x15, #28960, lsl 32
  movk x14, #47623, lsl 32
  movk x15, #17153, lsl 48
  dup.2d v11, x15
  movk x14, #9430, lsl 48
  mov.16b v12, v5
  mul x15, x10, x11
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  umulh x10, x10, x11
  fmla.2d v13, v8, v11
  add.2d v0, v0, v12
  adds x9, x15, x9
  cinc x10, x10, hs
  add.2d v11, v15, v13
  mul x15, x12, x11
  mov x16, #46128
  movk x16, #29964, lsl 16
  umulh x12, x12, x11
  movk x16, #7587, lsl 32
  adds x10, x15, x10
  cinc x12, x12, hs
  movk x16, #17161, lsl 48
  dup.2d v12, x16
  adds x0, x10, x0
  cinc x10, x12, hs
  mov.16b v13, v5
  mul x12, x13, x11
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  umulh x13, x13, x11
  fmla.2d v14, v8, v12
  adds x10, x12, x10
  cinc x12, x13, hs
  add.2d v1, v1, v13
  add.2d v0, v0, v14
  adds x1, x10, x1
  cinc x10, x12, hs
  mov x12, #52826
  movk x12, #57790, lsl 16
  mul x13, x14, x11
  movk x12, #55431, lsl 32
  umulh x11, x14, x11
  movk x12, #17196, lsl 48
  dup.2d v12, x12
  adds x10, x13, x10
  cinc x11, x11, hs
  mov.16b v13, v5
  adds x2, x10, x2
  cinc x10, x11, hs
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  add x3, x3, x10
  fmla.2d v14, v8, v12
  mov x10, #65535
  add.2d v2, v2, v13
  add.2d v1, v1, v14
  movk x10, #61439, lsl 16
  mov x11, #31276
  movk x10, #62867, lsl 32
  movk x11, #21262, lsl 16
  movk x11, #2304, lsl 32
  movk x10, #49889, lsl 48
  movk x11, #17182, lsl 48
  dup.2d v12, x11
  mul x10, x10, x9
  mov.16b v13, v5
  mov x11, #1
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  movk x11, #61440, lsl 16
  fmla.2d v14, v8, v12
  movk x11, #62867, lsl 32
  add.2d v7, v7, v13
  add.2d v2, v2, v14
  movk x11, #17377, lsl 48
  mov x12, #28672
  mov x13, #28817
  movk x12, #24515, lsl 16
  movk x12, #54929, lsl 32
  movk x13, #31161, lsl 16
  movk x12, #17064, lsl 48
  dup.2d v12, x12
  movk x13, #59464, lsl 32
  mov.16b v13, v5
  movk x13, #10291, lsl 48
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  mov x12, #22621
  fmla.2d v14, v8, v12
  movk x12, #33153, lsl 16
  add.2d v3, v3, v13
  add.2d v7, v7, v14
  movk x12, #17846, lsl 32
  ucvtf.2d v8, v9
  movk x12, #47184, lsl 48
  mov x14, #44768
  movk x14, #51919, lsl 16
  mov x15, #41001
  movk x14, #6346, lsl 32
  movk x15, #57649, lsl 16
  movk x14, #17133, lsl 48
  dup.2d v9, x14
  movk x15, #20082, lsl 32
  mov.16b v12, v5
  fmla.2d v12, v8, v9
  movk x15, #12388, lsl 48
  fsub.2d v13, v6, v12
  mul x14, x11, x10
  fmla.2d v13, v8, v9
  add.2d v0, v0, v12
  umulh x11, x11, x10
  add.2d v9, v11, v13
  cmn x14, x9
  cinc x11, x11, hs
  mov x9, #47492
  movk x9, #23630, lsl 16
  mul x14, x13, x10
  movk x9, #49985, lsl 32
  umulh x13, x13, x10
  movk x9, #17168, lsl 48
  dup.2d v11, x9
  adds x9, x14, x11
  cinc x11, x13, hs
  mov.16b v12, v5
  adds x0, x9, x0
  cinc x9, x11, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  mul x11, x12, x10
  fmla.2d v13, v8, v11
  add.2d v1, v1, v12
  umulh x12, x12, x10
  add.2d v0, v0, v13
  adds x9, x11, x9
  cinc x11, x12, hs
  mov x12, #57936
  movk x12, #54828, lsl 16
  adds x1, x9, x1
  cinc x9, x11, hs
  movk x12, #18292, lsl 32
  mul x11, x15, x10
  movk x12, #17197, lsl 48
  dup.2d v11, x12
  umulh x10, x15, x10
  mov.16b v12, v5
  adds x9, x11, x9
  cinc x10, x10, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  adds x2, x9, x2
  cinc x9, x10, hs
  fmla.2d v13, v8, v11
  add.2d v2, v2, v12
  add x3, x3, x9
  add.2d v1, v1, v13
  mul x9, x4, x4
  mov x10, #17708
  movk x10, #43915, lsl 16
  umulh x11, x4, x4
  movk x10, #64348, lsl 32
  mul x12, x4, x5
  movk x10, #17188, lsl 48
  dup.2d v11, x10
  umulh x10, x4, x5
  mov.16b v12, v5
  adds x11, x12, x11
  cinc x13, x10, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  mul x14, x4, x6
  fmla.2d v13, v8, v11
  umulh x15, x4, x6
  add.2d v7, v7, v12
  add.2d v2, v2, v13
  adds x13, x14, x13
  cinc x16, x15, hs
  mov x17, #29184
  movk x17, #20789, lsl 16
  mul x20, x4, x7
  movk x17, #19197, lsl 32
  umulh x4, x4, x7
  movk x17, #17083, lsl 48
  dup.2d v11, x17
  adds x16, x20, x16
  cinc x17, x4, hs
  mov.16b v12, v5
  adds x11, x12, x11
  cinc x10, x10, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  mul x12, x5, x5
  fmla.2d v13, v8, v11
  umulh x21, x5, x5
  add.2d v3, v3, v12
  add.2d v7, v7, v13
  adds x10, x12, x10
  cinc x12, x21, hs
  ucvtf.2d v8, v10
  adds x10, x10, x13
  cinc x12, x12, hs
  mov x13, #58856
  movk x13, #14953, lsl 16
  mul x21, x5, x6
  movk x13, #15155, lsl 32
  movk x13, #17181, lsl 48
  umulh x22, x5, x6
  dup.2d v10, x13
  adds x12, x21, x12
  cinc x13, x22, hs
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  adds x12, x12, x16
  cinc x13, x13, hs
  fsub.2d v12, v6, v11
  mul x16, x5, x7
  fmla.2d v12, v8, v10
  add.2d v0, v0, v11
  umulh x5, x5, x7
  add.2d v9, v9, v12
  adds x13, x16, x13
  cinc x23, x5, hs
  mov x24, #35392
  movk x24, #12477, lsl 16
  adds x13, x13, x17
  cinc x17, x23, hs
  movk x24, #56780, lsl 32
  adds x10, x14, x10
  cinc x14, x15, hs
  movk x24, #17142, lsl 48
  dup.2d v10, x24
  adds x14, x21, x14
  cinc x15, x22, hs
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  adds x12, x14, x12
  cinc x14, x15, hs
  fsub.2d v12, v6, v11
  mul x15, x6, x6
  fmla.2d v12, v8, v10
  add.2d v1, v1, v11
  umulh x21, x6, x6
  add.2d v0, v0, v12
  adds x14, x15, x14
  cinc x15, x21, hs
  mov x21, #9848
  movk x21, #54501, lsl 16
  adds x13, x14, x13
  cinc x14, x15, hs
  movk x21, #31540, lsl 32
  mul x15, x6, x7
  movk x21, #17170, lsl 48
  dup.2d v10, x21
  umulh x6, x6, x7
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  adds x14, x15, x14
  cinc x21, x6, hs
  fsub.2d v12, v6, v11
  adds x14, x14, x17
  cinc x17, x21, hs
  fmla.2d v12, v8, v10
  add.2d v2, v2, v11
  adds x12, x20, x12
  cinc x4, x4, hs
  add.2d v1, v1, v12
  adds x4, x16, x4
  cinc x5, x5, hs
  mov x16, #9584
  movk x16, #63883, lsl 16
  adds x4, x4, x13
  cinc x5, x5, hs
  movk x16, #18253, lsl 32
  adds x5, x15, x5
  cinc x6, x6, hs
  movk x16, #17190, lsl 48
  dup.2d v10, x16
  adds x5, x5, x14
  cinc x6, x6, hs
  mov.16b v11, v5
  mul x13, x7, x7
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  umulh x7, x7, x7
  fmla.2d v12, v8, v10
  add.2d v7, v7, v11
  adds x6, x13, x6
  cinc x7, x7, hs
  add.2d v2, v2, v12
  adds x6, x6, x17
  cinc x7, x7, hs
  mov x13, #51712
  movk x13, #16093, lsl 16
  mov x14, #56431
  movk x13, #30633, lsl 32
  movk x14, #30457, lsl 16
  movk x13, #17068, lsl 48
  dup.2d v10, x13
  movk x14, #30012, lsl 32
  mov.16b v11, v5
  movk x14, #6382, lsl 48
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  mov x13, #59151
  fmla.2d v12, v8, v10
  movk x13, #41769, lsl 16
  add.2d v3, v3, v11
  add.2d v7, v7, v12
  movk x13, #32276, lsl 32
  ucvtf.2d v4, v4
  mov x15, #34724
  movk x13, #21677, lsl 48
  movk x15, #40393, lsl 16
  mov x16, #34015
  movk x15, #23752, lsl 32
  movk x15, #17184, lsl 48
  movk x16, #20342, lsl 16
  dup.2d v8, x15
  movk x16, #13935, lsl 32
  mov.16b v10, v5
  fmla.2d v10, v4, v8
  movk x16, #11030, lsl 48
  fsub.2d v11, v6, v10
  mov x15, #13689
  fmla.2d v11, v4, v8
  add.2d v0, v0, v10
  movk x15, #8159, lsl 16
  add.2d v8, v9, v11
  movk x15, #215, lsl 32
  mov x17, #25532
  movk x17, #31025, lsl 16
  movk x15, #4913, lsl 48
  movk x17, #10002, lsl 32
  movk x17, #17199, lsl 48
  mul x20, x14, x9
  dup.2d v9, x17
  umulh x17, x14, x9
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  adds x10, x20, x10
  cinc x17, x17, hs
  fsub.2d v11, v6, v10
  mul x20, x13, x9
  fmla.2d v11, v4, v9
  add.2d v1, v1, v10
  umulh x21, x13, x9
  add.2d v0, v0, v11
  adds x17, x20, x17
  cinc x20, x21, hs
  mov x21, #18830
  movk x21, #2465, lsl 16
  adds x12, x17, x12
  cinc x17, x20, hs
  movk x21, #36348, lsl 32
  movk x21, #17194, lsl 48
  mul x20, x16, x9
  dup.2d v9, x21
  umulh x21, x16, x9
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  adds x17, x20, x17
  cinc x20, x21, hs
  fsub.2d v11, v6, v10
  adds x4, x17, x4
  cinc x17, x20, hs
  fmla.2d v11, v4, v9
  add.2d v2, v2, v10
  mul x20, x15, x9
  add.2d v1, v1, v11
  umulh x9, x15, x9
  mov x21, #21566
  movk x21, #43708, lsl 16
  adds x17, x20, x17
  cinc x9, x9, hs
  movk x21, #57685, lsl 32
  adds x5, x17, x5
  cinc x9, x9, hs
  movk x21, #17185, lsl 48
  dup.2d v9, x21
  adds x6, x6, x9
  cinc x7, x7, hs
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  mul x9, x14, x11
  fsub.2d v11, v6, v10
  umulh x14, x14, x11
  fmla.2d v11, v4, v9
  add.2d v7, v7, v10
  adds x9, x9, x12
  cinc x12, x14, hs
  add.2d v2, v2, v11
  mul x14, x13, x11
  mov x17, #3072
  movk x17, #8058, lsl 16
  umulh x13, x13, x11
  movk x17, #46097, lsl 32
  adds x12, x14, x12
  cinc x13, x13, hs
  movk x17, #17047, lsl 48
  dup.2d v9, x17
  adds x4, x12, x4
  cinc x12, x13, hs
  mov.16b v10, v5
  mul x13, x16, x11
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  umulh x14, x16, x11
  fmla.2d v11, v4, v9
  add.2d v3, v3, v10
  adds x12, x13, x12
  cinc x13, x14, hs
  add.2d v4, v7, v11
  adds x5, x12, x5
  cinc x12, x13, hs
  mov x13, #65535
  movk x13, #61439, lsl 16
  mul x14, x15, x11
  movk x13, #62867, lsl 32
  umulh x11, x15, x11
  movk x13, #1, lsl 48
  umov x15, v8.d[0]
  adds x12, x14, x12
  cinc x11, x11, hs
  umov x14, v8.d[1]
  adds x6, x12, x6
  cinc x11, x11, hs
  mul x12, x15, x13
  mul x13, x14, x13
  add x7, x7, x11
  and x11, x12, x8
  mov x12, #61005
  and x8, x13, x8
  ins v7.d[0], x11
  ins v7.d[1], x8
  movk x12, #58262, lsl 16
  ucvtf.2d v7, v7
  mov x8, #16
  movk x12, #32851, lsl 32
  movk x8, #22847, lsl 32
  movk x12, #11582, lsl 48
  movk x8, #17151, lsl 48
  dup.2d v9, x8
  mov x8, #37581
  mov.16b v10, v5
  movk x8, #43836, lsl 16
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  movk x8, #36286, lsl 32
  fmla.2d v11, v7, v9
  movk x8, #51783, lsl 48
  add.2d v0, v0, v10
  add.2d v8, v8, v11
  mov x11, #10899
  mov x13, #20728
  movk x13, #23588, lsl 16
  movk x11, #30709, lsl 16
  movk x13, #7790, lsl 32
  movk x11, #61551, lsl 32
  movk x13, #17170, lsl 48
  dup.2d v9, x13
  movk x11, #45784, lsl 48
  mov.16b v10, v5
  mov x13, #36612
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  movk x13, #63402, lsl 16
  fmla.2d v11, v7, v9
  movk x13, #47623, lsl 32
  add.2d v1, v1, v10
  add.2d v0, v0, v11
  movk x13, #9430, lsl 48
  mov x14, #16000
  mul x15, x12, x10
  movk x14, #53891, lsl 16
  movk x14, #5509, lsl 32
  umulh x12, x12, x10
  movk x14, #17144, lsl 48
  dup.2d v9, x14
  adds x9, x15, x9
  cinc x12, x12, hs
  mov.16b v10, v5
  mul x14, x8, x10
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  umulh x8, x8, x10
  fmla.2d v11, v7, v9
  adds x12, x14, x12
  cinc x8, x8, hs
  add.2d v2, v2, v10
  add.2d v1, v1, v11
  adds x4, x12, x4
  cinc x8, x8, hs
  mov x12, #46800
  mul x14, x11, x10
  movk x12, #2568, lsl 16
  movk x12, #1335, lsl 32
  umulh x11, x11, x10
  movk x12, #17188, lsl 48
  adds x8, x14, x8
  cinc x11, x11, hs
  dup.2d v9, x12
  mov.16b v10, v5
  adds x5, x8, x5
  cinc x8, x11, hs
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  mul x11, x13, x10
  fmla.2d v11, v7, v9
  umulh x10, x13, x10
  add.2d v4, v4, v10
  add.2d v2, v2, v11
  adds x8, x11, x8
  cinc x10, x10, hs
  mov x11, #39040
  adds x6, x8, x6
  cinc x8, x10, hs
  movk x11, #14704, lsl 16
  movk x11, #12839, lsl 32
  add x7, x7, x8
  movk x11, #17096, lsl 48
  mov x8, #65535
  dup.2d v9, x11
  mov.16b v5, v5
  movk x8, #61439, lsl 16
  fmla.2d v5, v7, v9
  movk x8, #62867, lsl 32
  fsub.2d v6, v6, v5
  fmla.2d v6, v7, v9
  movk x8, #49889, lsl 48
  add.2d v3, v3, v5
  add.2d v4, v4, v6
  mul x8, x8, x9
  mov x10, #140737488355328
  mov x11, #1
  dup.2d v5, x10
  and.16b v5, v3, v5
  movk x11, #61440, lsl 16
  cmeq.2d v5, v5, #0
  movk x11, #62867, lsl 32
  mov x10, #2
  movk x10, #57344, lsl 16
  movk x11, #17377, lsl 48
  movk x10, #60199, lsl 32
  mov x12, #28817
  movk x10, #3, lsl 48
  dup.2d v6, x10
  movk x12, #31161, lsl 16
  bic.16b v6, v6, v5
  mov x10, #10364
  movk x12, #59464, lsl 32
  movk x10, #11794, lsl 16
  movk x12, #10291, lsl 48
  movk x10, #3895, lsl 32
  movk x10, #9, lsl 48
  mov x13, #22621
  dup.2d v7, x10
  movk x13, #33153, lsl 16
  bic.16b v7, v7, v5
  mov x10, #26576
  movk x13, #17846, lsl 32
  movk x10, #47696, lsl 16
  movk x13, #47184, lsl 48
  movk x10, #688, lsl 32
  movk x10, #3, lsl 48
  mov x14, #41001
  dup.2d v9, x10
  movk x14, #57649, lsl 16
  bic.16b v9, v9, v5
  mov x10, #46800
  movk x14, #20082, lsl 32
  movk x10, #2568, lsl 16
  movk x10, #1335, lsl 32
  movk x14, #12388, lsl 48
  movk x10, #4, lsl 48
  mul x15, x11, x8
  dup.2d v10, x10
  bic.16b v10, v10, v5
  umulh x10, x11, x8
  mov x11, #49763
  cmn x15, x9
  cinc x10, x10, hs
  movk x11, #40165, lsl 16
  movk x11, #24776, lsl 32
  mul x9, x12, x8
  dup.2d v11, x11
  umulh x11, x12, x8
  bic.16b v5, v11, v5
  sub.2d v0, v0, v6
  adds x9, x9, x10
  cinc x10, x11, hs
  ssra.2d v0, v8, #52
  adds x4, x9, x4
  cinc x9, x10, hs
  sub.2d v6, v1, v7
  ssra.2d v6, v0, #52
  mul x10, x13, x8
  sub.2d v7, v2, v9
  ssra.2d v7, v6, #52
  umulh x11, x13, x8
  sub.2d v4, v4, v10
  adds x9, x10, x9
  cinc x10, x11, hs
  ssra.2d v4, v7, #52
  sub.2d v5, v3, v5
  adds x5, x9, x5
  cinc x9, x10, hs
  ssra.2d v5, v4, #52
  mul x10, x14, x8
  ushr.2d v1, v6, #12
  ushr.2d v2, v7, #24
  umulh x8, x14, x8
  ushr.2d v3, v4, #36
  adds x9, x10, x9
  cinc x8, x8, hs
  sli.2d v0, v6, #52
  sli.2d v1, v7, #40
  adds x6, x9, x6
  cinc x8, x8, hs
  sli.2d v2, v4, #28
  sli.2d v3, v5, #16
  add x7, x7, x8
