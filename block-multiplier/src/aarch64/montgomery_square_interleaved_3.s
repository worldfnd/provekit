// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("v0") av[0], in("v1") av[1], in("v2") av[2], in("v3") av[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("v0") outv[0], lateout("v1") outv[1], lateout("v2") outv[2], lateout("v3") outv[3],
// lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _, lateout("v4") _, lateout("v5") _, lateout("v6") _, lateout("v7") _, lateout("v8") _, lateout("v9") _, lateout("v10") _, lateout("v11") _, lateout("v12") _, lateout("v13") _, lateout("v14") _, lateout("v15") _, lateout("v16") _, lateout("v17") _, lateout("v18") _, lateout("v19") _,
// lateout("lr") _
  mov x4, #4503599627370495
  dup.2d v4, x4
  mul x5, x0, x0
  mov x6, #5075556780046548992
  dup.2d v5, x6
  mov x6, #1
  umulh x7, x0, x0
  movk x6, #18032, lsl 48
  dup.2d v6, x6
  shl.2d v7, v1, #14
  mul x6, x0, x1
  shl.2d v8, v2, #26
  shl.2d v9, v3, #38
  ushr.2d v3, v3, #14
  umulh x8, x0, x1
  shl.2d v10, v0, #2
  usra.2d v7, v0, #50
  usra.2d v8, v1, #38
  adds x7, x6, x7
  cinc x9, x8, hs
  usra.2d v9, v2, #26
  and.16b v0, v10, v4
  and.16b v1, v7, v4
  mul x10, x0, x2
  and.16b v2, v8, v4
  and.16b v7, v9, v4
  umulh x11, x0, x2
  mov x12, #13605374474286268416
  dup.2d v8, x12
  mov x12, #6440147467139809280
  adds x9, x10, x9
  cinc x13, x11, hs
  dup.2d v9, x12
  mov x12, #3688448094816436224
  dup.2d v10, x12
  mul x12, x0, x3
  mov x14, #9209861237972664320
  dup.2d v11, x14
  mov x14, #12218265789056155648
  umulh x0, x0, x3
  dup.2d v12, x14
  mov x14, #17739678932212383744
  dup.2d v13, x14
  adds x13, x12, x13
  cinc x14, x0, hs
  mov x15, #2301339409586323456
  dup.2d v14, x15
  mov x15, #7822752552742551552
  adds x6, x6, x7
  cinc x7, x8, hs
  dup.2d v15, x15
  mov x8, #5071053180419178496
  mul x15, x1, x1
  dup.2d v16, x8
  mov x8, #16352570246982270976
  dup.2d v17, x8
  umulh x8, x1, x1
  ucvtf.2d v0, v0
  ucvtf.2d v1, v1
  ucvtf.2d v2, v2
  adds x7, x15, x7
  cinc x8, x8, hs
  ucvtf.2d v7, v7
  ucvtf.2d v3, v3
  mov.16b v18, v5
  adds x7, x7, x9
  cinc x8, x8, hs
  fmla.2d v18, v0, v0
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v0
  mul x9, x1, x2
  add.2d v10, v10, v18
  add.2d v8, v8, v19
  mov.16b v18, v5
  umulh x15, x1, x2
  fmla.2d v18, v0, v1
  fsub.2d v19, v6, v18
  adds x8, x9, x8
  cinc x16, x15, hs
  fmla.2d v19, v0, v1
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  adds x8, x8, x13
  cinc x13, x16, hs
  add.2d v12, v12, v18
  add.2d v10, v10, v19
  mov.16b v18, v5
  mul x16, x1, x3
  fmla.2d v18, v0, v2
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v2
  umulh x1, x1, x3
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  add.2d v14, v14, v18
  adds x13, x16, x13
  cinc x17, x1, hs
  add.2d v12, v12, v19
  mov.16b v18, v5
  fmla.2d v18, v0, v7
  adds x13, x13, x14
  cinc x14, x17, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v7
  adds x7, x10, x7
  cinc x10, x11, hs
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  add.2d v16, v16, v18
  adds x9, x9, x10
  cinc x10, x15, hs
  add.2d v14, v14, v19
  mov.16b v18, v5
  fmla.2d v18, v0, v3
  adds x8, x9, x8
  cinc x9, x10, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v3
  add.2d v0, v18, v18
  mul x10, x2, x2
  add.2d v18, v19, v19
  add.2d v0, v17, v0
  add.2d v16, v16, v18
  umulh x11, x2, x2
  mov.16b v17, v5
  fmla.2d v17, v1, v1
  fsub.2d v18, v6, v17
  adds x9, x10, x9
  cinc x10, x11, hs
  fmla.2d v18, v1, v1
  add.2d v14, v14, v17
  adds x9, x9, x13
  cinc x10, x10, hs
  add.2d v12, v12, v18
  mov.16b v17, v5
  fmla.2d v17, v1, v2
  mul x11, x2, x3
  fsub.2d v18, v6, v17
  fmla.2d v18, v1, v2
  add.2d v17, v17, v17
  umulh x2, x2, x3
  add.2d v18, v18, v18
  add.2d v16, v16, v17
  add.2d v14, v14, v18
  adds x10, x11, x10
  cinc x13, x2, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v7
  fsub.2d v18, v6, v17
  adds x10, x10, x14
  cinc x13, x13, hs
  fmla.2d v18, v1, v7
  add.2d v17, v17, v17
  add.2d v18, v18, v18
  adds x8, x12, x8
  cinc x0, x0, hs
  add.2d v0, v0, v17
  add.2d v16, v16, v18
  adds x0, x16, x0
  cinc x1, x1, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v3
  fsub.2d v18, v6, v17
  adds x0, x0, x9
  cinc x1, x1, hs
  fmla.2d v18, v1, v3
  add.2d v1, v17, v17
  add.2d v17, v18, v18
  adds x1, x11, x1
  cinc x2, x2, hs
  add.2d v1, v15, v1
  add.2d v0, v0, v17
  mov.16b v15, v5
  adds x1, x1, x10
  cinc x2, x2, hs
  fmla.2d v15, v2, v2
  fsub.2d v17, v6, v15
  fmla.2d v17, v2, v2
  mul x9, x3, x3
  add.2d v0, v0, v15
  add.2d v15, v16, v17
  mov.16b v16, v5
  umulh x3, x3, x3
  fmla.2d v16, v2, v7
  fsub.2d v17, v6, v16
  adds x2, x9, x2
  cinc x3, x3, hs
  fmla.2d v17, v2, v7
  add.2d v16, v16, v16
  add.2d v17, v17, v17
  adds x2, x2, x13
  cinc x3, x3, hs
  add.2d v1, v1, v16
  add.2d v0, v0, v17
  mov.16b v16, v5
  mov x9, #48718
  fmla.2d v16, v2, v3
  fsub.2d v17, v6, v16
  fmla.2d v17, v2, v3
  movk x9, #4732, lsl 16
  add.2d v2, v16, v16
  add.2d v16, v17, v17
  add.2d v2, v13, v2
  movk x9, #45078, lsl 32
  add.2d v1, v1, v16
  mov.16b v13, v5
  fmla.2d v13, v7, v7
  movk x9, #39852, lsl 48
  fsub.2d v16, v6, v13
  fmla.2d v16, v7, v7
  mov x10, #16676
  add.2d v2, v2, v13
  add.2d v1, v1, v16
  mov.16b v13, v5
  movk x10, #12692, lsl 16
  fmla.2d v13, v7, v3
  fsub.2d v16, v6, v13
  fmla.2d v16, v7, v3
  movk x10, #20986, lsl 32
  add.2d v7, v13, v13
  add.2d v13, v16, v16
  add.2d v7, v11, v7
  movk x10, #2848, lsl 48
  add.2d v2, v2, v13
  mov.16b v11, v5
  fmla.2d v11, v3, v3
  mov x11, #51052
  fsub.2d v13, v6, v11
  fmla.2d v13, v3, v3
  add.2d v3, v9, v11
  movk x11, #24721, lsl 16
  add.2d v7, v7, v13
  usra.2d v10, v8, #52
  movk x11, #61092, lsl 32
  usra.2d v12, v10, #52
  usra.2d v14, v12, #52
  usra.2d v15, v14, #52
  movk x11, #45156, lsl 48
  and.16b v8, v8, v4
  and.16b v9, v10, v4
  and.16b v10, v12, v4
  mov x12, #3197
  and.16b v4, v14, v4
  ucvtf.2d v8, v8
  mov x13, #37864
  movk x12, #18936, lsl 16
  movk x13, #1815, lsl 16
  movk x13, #28960, lsl 32
  movk x13, #17153, lsl 48
  movk x12, #10922, lsl 32
  dup.2d v11, x13
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  movk x12, #11014, lsl 48
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v11
  add.2d v0, v0, v12
  mul x13, x9, x5
  add.2d v11, v15, v13
  mov x14, #46128
  umulh x9, x9, x5
  movk x14, #29964, lsl 16
  movk x14, #7587, lsl 32
  movk x14, #17161, lsl 48
  adds x8, x13, x8
  cinc x9, x9, hs
  dup.2d v12, x14
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  mul x13, x10, x5
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  add.2d v1, v1, v13
  umulh x10, x10, x5
  add.2d v0, v0, v14
  mov x14, #52826
  movk x14, #57790, lsl 16
  adds x9, x13, x9
  cinc x10, x10, hs
  movk x14, #55431, lsl 32
  movk x14, #17196, lsl 48
  dup.2d v12, x14
  adds x0, x9, x0
  cinc x9, x10, hs
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  mul x10, x11, x5
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  add.2d v2, v2, v13
  umulh x11, x11, x5
  add.2d v1, v1, v14
  mov x13, #31276
  movk x13, #21262, lsl 16
  adds x9, x10, x9
  cinc x10, x11, hs
  movk x13, #2304, lsl 32
  movk x13, #17182, lsl 48
  dup.2d v12, x13
  adds x1, x9, x1
  cinc x9, x10, hs
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  mul x10, x12, x5
  fmla.2d v14, v8, v12
  add.2d v7, v7, v13
  add.2d v2, v2, v14
  umulh x5, x12, x5
  mov x11, #28672
  movk x11, #24515, lsl 16
  adds x9, x10, x9
  cinc x5, x5, hs
  movk x11, #54929, lsl 32
  movk x11, #17064, lsl 48
  dup.2d v12, x11
  adds x2, x9, x2
  cinc x5, x5, hs
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  add x3, x3, x5
  fmla.2d v14, v8, v12
  add.2d v3, v3, v13
  add.2d v7, v7, v14
  mov x5, #56431
  ucvtf.2d v8, v9
  mov x9, #44768
  movk x9, #51919, lsl 16
  movk x5, #30457, lsl 16
  movk x9, #6346, lsl 32
  movk x9, #17133, lsl 48
  dup.2d v9, x9
  movk x5, #30012, lsl 32
  mov.16b v12, v5
  fmla.2d v12, v8, v9
  movk x5, #6382, lsl 48
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v9
  add.2d v0, v0, v12
  mov x9, #59151
  add.2d v9, v11, v13
  mov x10, #47492
  movk x10, #23630, lsl 16
  movk x9, #41769, lsl 16
  movk x10, #49985, lsl 32
  movk x10, #17168, lsl 48
  dup.2d v11, x10
  movk x9, #32276, lsl 32
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  movk x9, #21677, lsl 48
  fmla.2d v13, v8, v11
  add.2d v1, v1, v12
  add.2d v0, v0, v13
  mov x10, #34015
  mov x11, #57936
  movk x11, #54828, lsl 16
  movk x10, #20342, lsl 16
  movk x11, #18292, lsl 32
  movk x11, #17197, lsl 48
  dup.2d v11, x11
  movk x10, #13935, lsl 32
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  movk x10, #11030, lsl 48
  fmla.2d v13, v8, v11
  add.2d v2, v2, v12
  add.2d v1, v1, v13
  mov x11, #13689
  mov x12, #17708
  movk x12, #43915, lsl 16
  movk x12, #64348, lsl 32
  movk x11, #8159, lsl 16
  movk x12, #17188, lsl 48
  dup.2d v11, x12
  mov.16b v12, v5
  movk x11, #215, lsl 32
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  movk x11, #4913, lsl 48
  fmla.2d v13, v8, v11
  add.2d v7, v7, v12
  add.2d v2, v2, v13
  mul x12, x5, x6
  mov x13, #29184
  movk x13, #20789, lsl 16
  movk x13, #19197, lsl 32
  umulh x5, x5, x6
  movk x13, #17083, lsl 48
  dup.2d v11, x13
  mov.16b v12, v5
  adds x8, x12, x8
  cinc x5, x5, hs
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v11
  mul x12, x9, x6
  add.2d v3, v3, v12
  add.2d v7, v7, v13
  ucvtf.2d v8, v10
  umulh x9, x9, x6
  mov x13, #58856
  movk x13, #14953, lsl 16
  adds x5, x12, x5
  cinc x9, x9, hs
  movk x13, #15155, lsl 32
  movk x13, #17181, lsl 48
  dup.2d v10, x13
  adds x0, x5, x0
  cinc x5, x9, hs
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  mul x9, x10, x6
  fmla.2d v12, v8, v10
  add.2d v0, v0, v11
  add.2d v9, v9, v12
  umulh x10, x10, x6
  mov x12, #35392
  movk x12, #12477, lsl 16
  movk x12, #56780, lsl 32
  adds x5, x9, x5
  cinc x9, x10, hs
  movk x12, #17142, lsl 48
  dup.2d v10, x12
  mov.16b v11, v5
  adds x1, x5, x1
  cinc x5, x9, hs
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  mul x9, x11, x6
  fmla.2d v12, v8, v10
  add.2d v1, v1, v11
  add.2d v0, v0, v12
  umulh x6, x11, x6
  mov x10, #9848
  movk x10, #54501, lsl 16
  movk x10, #31540, lsl 32
  adds x5, x9, x5
  cinc x6, x6, hs
  movk x10, #17170, lsl 48
  dup.2d v10, x10
  mov.16b v11, v5
  adds x2, x5, x2
  cinc x5, x6, hs
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  add x3, x3, x5
  add.2d v2, v2, v11
  add.2d v1, v1, v12
  mov x5, #9584
  mov x6, #61005
  movk x5, #63883, lsl 16
  movk x5, #18253, lsl 32
  movk x6, #58262, lsl 16
  movk x5, #17190, lsl 48
  dup.2d v10, x5
  mov.16b v11, v5
  movk x6, #32851, lsl 32
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  movk x6, #11582, lsl 48
  add.2d v7, v7, v11
  add.2d v2, v2, v12
  mov x5, #51712
  mov x9, #37581
  movk x5, #16093, lsl 16
  movk x5, #30633, lsl 32
  movk x5, #17068, lsl 48
  movk x9, #43836, lsl 16
  dup.2d v10, x5
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  movk x9, #36286, lsl 32
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  movk x9, #51783, lsl 48
  add.2d v3, v3, v11
  add.2d v7, v7, v12
  ucvtf.2d v4, v4
  mov x5, #10899
  mov x10, #34724
  movk x10, #40393, lsl 16
  movk x10, #23752, lsl 32
  movk x5, #30709, lsl 16
  movk x10, #17184, lsl 48
  dup.2d v8, x10
  mov.16b v10, v5
  movk x5, #61551, lsl 32
  fmla.2d v10, v4, v8
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v8
  movk x5, #45784, lsl 48
  add.2d v0, v0, v10
  add.2d v8, v9, v11
  mov x10, #25532
  mov x11, #36612
  movk x10, #31025, lsl 16
  movk x10, #10002, lsl 32
  movk x10, #17199, lsl 48
  movk x11, #63402, lsl 16
  dup.2d v9, x10
  mov.16b v10, v5
  movk x11, #47623, lsl 32
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  movk x11, #9430, lsl 48
  add.2d v1, v1, v10
  add.2d v0, v0, v11
  mov x10, #18830
  mul x12, x6, x7
  movk x10, #2465, lsl 16
  movk x10, #36348, lsl 32
  movk x10, #17194, lsl 48
  umulh x6, x6, x7
  dup.2d v9, x10
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  adds x8, x12, x8
  cinc x6, x6, hs
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  add.2d v2, v2, v10
  mul x10, x9, x7
  add.2d v1, v1, v11
  mov x12, #21566
  umulh x9, x9, x7
  movk x12, #43708, lsl 16
  movk x12, #57685, lsl 32
  movk x12, #17185, lsl 48
  adds x6, x10, x6
  cinc x9, x9, hs
  dup.2d v9, x12
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  adds x0, x6, x0
  cinc x6, x9, hs
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  add.2d v7, v7, v10
  mul x9, x5, x7
  add.2d v2, v2, v11
  mov x10, #3072
  movk x10, #8058, lsl 16
  umulh x5, x5, x7
  movk x10, #46097, lsl 32
  movk x10, #17047, lsl 48
  dup.2d v9, x10
  adds x6, x9, x6
  cinc x5, x5, hs
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  adds x1, x6, x1
  cinc x5, x5, hs
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  add.2d v3, v3, v10
  mul x6, x11, x7
  add.2d v4, v7, v11
  mov x9, #65535
  movk x9, #61439, lsl 16
  umulh x7, x11, x7
  movk x9, #62867, lsl 32
  movk x9, #1, lsl 48
  umov x10, v8.d[0]
  adds x5, x6, x5
  cinc x6, x7, hs
  umov x7, v8.d[1]
  mul x10, x10, x9
  mul x7, x7, x9
  adds x2, x5, x2
  cinc x5, x6, hs
  and x6, x10, x4
  and x4, x7, x4
  ins v7.d[0], x6
  ins v7.d[1], x4
  add x3, x3, x5
  ucvtf.2d v7, v7
  mov x4, #16
  mov x5, #65535
  movk x4, #22847, lsl 32
  movk x4, #17151, lsl 48
  dup.2d v9, x4
  movk x5, #61439, lsl 16
  mov.16b v10, v5
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  movk x5, #62867, lsl 32
  fmla.2d v11, v7, v9
  add.2d v0, v0, v10
  add.2d v8, v8, v11
  movk x5, #49889, lsl 48
  mov x4, #20728
  movk x4, #23588, lsl 16
  movk x4, #7790, lsl 32
  mul x5, x5, x8
  movk x4, #17170, lsl 48
  dup.2d v9, x4
  mov.16b v10, v5
  mov x4, #1
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  movk x4, #61440, lsl 16
  fmla.2d v11, v7, v9
  add.2d v1, v1, v10
  add.2d v0, v0, v11
  movk x4, #62867, lsl 32
  mov x6, #16000
  movk x6, #53891, lsl 16
  movk x6, #5509, lsl 32
  movk x4, #17377, lsl 48
  movk x6, #17144, lsl 48
  dup.2d v9, x6
  mov.16b v10, v5
  mov x6, #28817
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v9
  movk x6, #31161, lsl 16
  add.2d v2, v2, v10
  add.2d v1, v1, v11
  mov x7, #46800
  movk x6, #59464, lsl 32
  movk x7, #2568, lsl 16
  movk x7, #1335, lsl 32
  movk x6, #10291, lsl 48
  movk x7, #17188, lsl 48
  dup.2d v9, x7
  mov.16b v10, v5
  mov x7, #22621
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v9
  movk x7, #33153, lsl 16
  add.2d v4, v4, v10
  add.2d v2, v2, v11
  mov x9, #39040
  movk x7, #17846, lsl 32
  movk x9, #14704, lsl 16
  movk x9, #12839, lsl 32
  movk x9, #17096, lsl 48
  movk x7, #47184, lsl 48
  dup.2d v9, x9
  mov.16b v5, v5
  fmla.2d v5, v7, v9
  mov x9, #41001
  fsub.2d v6, v6, v5
  fmla.2d v6, v7, v9
  movk x9, #57649, lsl 16
  add.2d v3, v3, v5
  add.2d v4, v4, v6
  mov x10, #140737488355328
  movk x9, #20082, lsl 32
  dup.2d v5, x10
  and.16b v5, v3, v5
  cmeq.2d v5, v5, #0
  movk x9, #12388, lsl 48
  mov x10, #2
  movk x10, #57344, lsl 16
  movk x10, #60199, lsl 32
  mul x11, x4, x5
  movk x10, #3, lsl 48
  dup.2d v6, x10
  bic.16b v6, v6, v5
  umulh x4, x4, x5
  mov x10, #10364
  movk x10, #11794, lsl 16
  movk x10, #3895, lsl 32
  cmn x11, x8
  cinc x4, x4, hs
  movk x10, #9, lsl 48
  dup.2d v7, x10
  mul x8, x6, x5
  bic.16b v7, v7, v5
  mov x10, #26576
  movk x10, #47696, lsl 16
  umulh x6, x6, x5
  movk x10, #688, lsl 32
  movk x10, #3, lsl 48
  dup.2d v9, x10
  adds x4, x8, x4
  cinc x6, x6, hs
  bic.16b v9, v9, v5
  mov x8, #46800
  movk x8, #2568, lsl 16
  adds x0, x4, x0
  cinc x4, x6, hs
  movk x8, #1335, lsl 32
  movk x8, #4, lsl 48
  dup.2d v10, x8
  mul x6, x7, x5
  bic.16b v10, v10, v5
  mov x8, #49763
  movk x8, #40165, lsl 16
  umulh x7, x7, x5
  movk x8, #24776, lsl 32
  dup.2d v11, x8
  adds x4, x6, x4
  cinc x6, x7, hs
  bic.16b v5, v11, v5
  sub.2d v0, v0, v6
  ssra.2d v0, v8, #52
  adds x1, x4, x1
  cinc x4, x6, hs
  sub.2d v6, v1, v7
  ssra.2d v6, v0, #52
  sub.2d v7, v2, v9
  mul x6, x9, x5
  ssra.2d v7, v6, #52
  sub.2d v4, v4, v10
  ssra.2d v4, v7, #52
  umulh x5, x9, x5
  sub.2d v5, v3, v5
  ssra.2d v5, v4, #52
  ushr.2d v1, v6, #12
  adds x4, x6, x4
  cinc x5, x5, hs
  ushr.2d v2, v7, #24
  ushr.2d v3, v4, #36
  sli.2d v0, v6, #52
  adds x2, x4, x2
  cinc x4, x5, hs
  sli.2d v1, v7, #40
  sli.2d v2, v4, #28
  sli.2d v3, v5, #16
  add x3, x3, x4
