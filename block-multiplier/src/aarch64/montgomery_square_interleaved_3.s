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
  mul x6, x0, x1
  shl.2d v7, v1, #14
  shl.2d v8, v2, #26
  shl.2d v9, v3, #38
  umulh x8, x0, x1
  ushr.2d v3, v3, #14
  shl.2d v10, v0, #2
  usra.2d v7, v0, #50
  adds x7, x6, x7
  cinc x9, x8, hs
  usra.2d v8, v1, #38
  usra.2d v9, v2, #26
  mul x10, x0, x2
  and.16b v0, v10, v4
  and.16b v1, v7, v4
  and.16b v2, v8, v4
  umulh x11, x0, x2
  and.16b v7, v9, v4
  mov x12, #13605374474286268416
  adds x9, x10, x9
  cinc x13, x11, hs
  dup.2d v8, x12
  mov x12, #6440147467139809280
  dup.2d v9, x12
  mul x12, x0, x3
  mov x14, #3688448094816436224
  dup.2d v10, x14
  mov x14, #9209861237972664320
  umulh x0, x0, x3
  dup.2d v11, x14
  mov x14, #12218265789056155648
  adds x13, x12, x13
  cinc x15, x0, hs
  dup.2d v12, x14
  mov x14, #17739678932212383744
  dup.2d v13, x14
  adds x6, x6, x7
  cinc x7, x8, hs
  mov x8, #2301339409586323456
  dup.2d v14, x8
  mov x8, #7822752552742551552
  mul x14, x1, x1
  dup.2d v15, x8
  mov x8, #5071053180419178496
  umulh x16, x1, x1
  dup.2d v16, x8
  mov x8, #16352570246982270976
  dup.2d v17, x8
  adds x7, x14, x7
  cinc x8, x16, hs
  ucvtf.2d v0, v0
  ucvtf.2d v1, v1
  adds x7, x7, x9
  cinc x8, x8, hs
  ucvtf.2d v2, v2
  ucvtf.2d v7, v7
  ucvtf.2d v3, v3
  mul x9, x1, x2
  mov.16b v18, v5
  fmla.2d v18, v0, v0
  fsub.2d v19, v6, v18
  umulh x14, x1, x2
  fmla.2d v19, v0, v0
  add.2d v10, v10, v18
  adds x8, x9, x8
  cinc x16, x14, hs
  add.2d v8, v8, v19
  mov.16b v18, v5
  fmla.2d v18, v0, v1
  adds x8, x8, x13
  cinc x13, x16, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v1
  add.2d v18, v18, v18
  mul x16, x1, x3
  add.2d v19, v19, v19
  add.2d v12, v12, v18
  umulh x1, x1, x3
  add.2d v10, v10, v19
  mov.16b v18, v5
  fmla.2d v18, v0, v2
  adds x13, x16, x13
  cinc x17, x1, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v2
  adds x13, x13, x15
  cinc x15, x17, hs
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  add.2d v14, v14, v18
  adds x7, x10, x7
  cinc x10, x11, hs
  add.2d v12, v12, v19
  mov.16b v18, v5
  fmla.2d v18, v0, v7
  adds x9, x9, x10
  cinc x10, x14, hs
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v7
  adds x8, x9, x8
  cinc x9, x10, hs
  add.2d v18, v18, v18
  add.2d v19, v19, v19
  add.2d v16, v16, v18
  mul x10, x2, x2
  add.2d v14, v14, v19
  mov.16b v18, v5
  fmla.2d v18, v0, v3
  umulh x11, x2, x2
  fsub.2d v19, v6, v18
  fmla.2d v19, v0, v3
  adds x9, x10, x9
  cinc x10, x11, hs
  add.2d v0, v18, v18
  add.2d v18, v19, v19
  add.2d v0, v17, v0
  adds x9, x9, x13
  cinc x10, x10, hs
  add.2d v16, v16, v18
  mov.16b v17, v5
  mul x11, x2, x3
  fmla.2d v17, v1, v1
  fsub.2d v18, v6, v17
  fmla.2d v18, v1, v1
  umulh x2, x2, x3
  add.2d v14, v14, v17
  add.2d v12, v12, v18
  mov.16b v17, v5
  adds x10, x11, x10
  cinc x13, x2, hs
  fmla.2d v17, v1, v2
  fsub.2d v18, v6, v17
  adds x10, x10, x15
  cinc x13, x13, hs
  fmla.2d v18, v1, v2
  add.2d v17, v17, v17
  add.2d v18, v18, v18
  adds x8, x12, x8
  cinc x0, x0, hs
  add.2d v16, v16, v17
  add.2d v14, v14, v18
  adds x0, x16, x0
  cinc x1, x1, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v7
  fsub.2d v18, v6, v17
  adds x0, x0, x9
  cinc x1, x1, hs
  fmla.2d v18, v1, v7
  add.2d v17, v17, v17
  add.2d v18, v18, v18
  adds x1, x11, x1
  cinc x2, x2, hs
  add.2d v0, v0, v17
  add.2d v16, v16, v18
  adds x1, x1, x10
  cinc x2, x2, hs
  mov.16b v17, v5
  fmla.2d v17, v1, v3
  fsub.2d v18, v6, v17
  mul x9, x3, x3
  fmla.2d v18, v1, v3
  add.2d v1, v17, v17
  add.2d v17, v18, v18
  umulh x3, x3, x3
  add.2d v1, v15, v1
  add.2d v0, v0, v17
  adds x2, x9, x2
  cinc x3, x3, hs
  mov.16b v15, v5
  fmla.2d v15, v2, v2
  fsub.2d v17, v6, v15
  adds x2, x2, x13
  cinc x3, x3, hs
  fmla.2d v17, v2, v2
  add.2d v0, v0, v15
  mov x9, #48718
  add.2d v15, v16, v17
  mov.16b v16, v5
  fmla.2d v16, v2, v7
  movk x9, #4732, lsl 16
  fsub.2d v17, v6, v16
  fmla.2d v17, v2, v7
  add.2d v16, v16, v16
  movk x9, #45078, lsl 32
  add.2d v17, v17, v17
  add.2d v1, v1, v16
  movk x9, #39852, lsl 48
  add.2d v0, v0, v17
  mov.16b v16, v5
  fmla.2d v16, v2, v3
  mov x10, #16676
  fsub.2d v17, v6, v16
  fmla.2d v17, v2, v3
  add.2d v2, v16, v16
  movk x10, #12692, lsl 16
  add.2d v16, v17, v17
  add.2d v2, v13, v2
  movk x10, #20986, lsl 32
  add.2d v1, v1, v16
  mov.16b v13, v5
  fmla.2d v13, v7, v7
  movk x10, #2848, lsl 48
  fsub.2d v16, v6, v13
  fmla.2d v16, v7, v7
  mov x11, #51052
  add.2d v2, v2, v13
  add.2d v1, v1, v16
  mov.16b v13, v5
  movk x11, #24721, lsl 16
  fmla.2d v13, v7, v3
  fsub.2d v16, v6, v13
  fmla.2d v16, v7, v3
  movk x11, #61092, lsl 32
  add.2d v7, v13, v13
  add.2d v13, v16, v16
  movk x11, #45156, lsl 48
  add.2d v7, v11, v7
  add.2d v2, v2, v13
  mov.16b v11, v5
  mov x12, #3197
  fmla.2d v11, v3, v3
  fsub.2d v13, v6, v11
  fmla.2d v13, v3, v3
  movk x12, #18936, lsl 16
  add.2d v3, v9, v11
  add.2d v7, v7, v13
  movk x12, #10922, lsl 32
  usra.2d v10, v8, #52
  usra.2d v12, v10, #52
  usra.2d v14, v12, #52
  movk x12, #11014, lsl 48
  usra.2d v15, v14, #52
  and.16b v8, v8, v4
  mul x13, x9, x5
  and.16b v9, v10, v4
  and.16b v10, v12, v4
  and.16b v4, v14, v4
  umulh x9, x9, x5
  ucvtf.2d v8, v8
  mov x14, #37864
  movk x14, #1815, lsl 16
  adds x8, x13, x8
  cinc x9, x9, hs
  movk x14, #28960, lsl 32
  movk x14, #17153, lsl 48
  mul x13, x10, x5
  dup.2d v11, x14
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  umulh x10, x10, x5
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v11
  add.2d v0, v0, v12
  adds x9, x13, x9
  cinc x10, x10, hs
  add.2d v11, v15, v13
  mov x13, #46128
  adds x0, x9, x0
  cinc x9, x10, hs
  movk x13, #29964, lsl 16
  movk x13, #7587, lsl 32
  movk x13, #17161, lsl 48
  mul x10, x11, x5
  dup.2d v12, x13
  mov.16b v13, v5
  umulh x11, x11, x5
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  adds x9, x10, x9
  cinc x10, x11, hs
  add.2d v1, v1, v13
  add.2d v0, v0, v14
  mov x11, #52826
  adds x1, x9, x1
  cinc x9, x10, hs
  movk x11, #57790, lsl 16
  movk x11, #55431, lsl 32
  mul x10, x12, x5
  movk x11, #17196, lsl 48
  dup.2d v12, x11
  mov.16b v13, v5
  umulh x5, x12, x5
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  adds x9, x10, x9
  cinc x5, x5, hs
  fmla.2d v14, v8, v12
  add.2d v2, v2, v13
  add.2d v1, v1, v14
  adds x2, x9, x2
  cinc x5, x5, hs
  mov x9, #31276
  movk x9, #21262, lsl 16
  movk x9, #2304, lsl 32
  add x3, x3, x5
  movk x9, #17182, lsl 48
  dup.2d v12, x9
  mov x5, #56431
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  fsub.2d v14, v6, v13
  movk x5, #30457, lsl 16
  fmla.2d v14, v8, v12
  add.2d v7, v7, v13
  add.2d v2, v2, v14
  movk x5, #30012, lsl 32
  mov x9, #28672
  movk x9, #24515, lsl 16
  movk x5, #6382, lsl 48
  movk x9, #54929, lsl 32
  movk x9, #17064, lsl 48
  dup.2d v12, x9
  mov x9, #59151
  mov.16b v13, v5
  fmla.2d v13, v8, v12
  movk x9, #41769, lsl 16
  fsub.2d v14, v6, v13
  fmla.2d v14, v8, v12
  add.2d v3, v3, v13
  movk x9, #32276, lsl 32
  add.2d v7, v7, v14
  ucvtf.2d v8, v9
  mov x10, #44768
  movk x9, #21677, lsl 48
  movk x10, #51919, lsl 16
  movk x10, #6346, lsl 32
  mov x11, #34015
  movk x10, #17133, lsl 48
  dup.2d v9, x10
  mov.16b v12, v5
  movk x11, #20342, lsl 16
  fmla.2d v12, v8, v9
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v9
  movk x11, #13935, lsl 32
  add.2d v0, v0, v12
  add.2d v9, v11, v13
  movk x11, #11030, lsl 48
  mov x10, #47492
  movk x10, #23630, lsl 16
  movk x10, #49985, lsl 32
  mov x12, #13689
  movk x10, #17168, lsl 48
  dup.2d v11, x10
  movk x12, #8159, lsl 16
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  movk x12, #215, lsl 32
  fmla.2d v13, v8, v11
  add.2d v1, v1, v12
  add.2d v0, v0, v13
  movk x12, #4913, lsl 48
  mov x10, #57936
  movk x10, #54828, lsl 16
  mul x13, x5, x6
  movk x10, #18292, lsl 32
  movk x10, #17197, lsl 48
  dup.2d v11, x10
  umulh x5, x5, x6
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  fsub.2d v13, v6, v12
  adds x8, x13, x8
  cinc x5, x5, hs
  fmla.2d v13, v8, v11
  add.2d v2, v2, v12
  mul x10, x9, x6
  add.2d v1, v1, v13
  mov x13, #17708
  movk x13, #43915, lsl 16
  umulh x9, x9, x6
  movk x13, #64348, lsl 32
  movk x13, #17188, lsl 48
  adds x5, x10, x5
  cinc x9, x9, hs
  dup.2d v11, x13
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  adds x0, x5, x0
  cinc x5, x9, hs
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v11
  add.2d v7, v7, v12
  mul x9, x11, x6
  add.2d v2, v2, v13
  mov x10, #29184
  umulh x11, x11, x6
  movk x10, #20789, lsl 16
  movk x10, #19197, lsl 32
  movk x10, #17083, lsl 48
  adds x5, x9, x5
  cinc x9, x11, hs
  dup.2d v11, x10
  mov.16b v12, v5
  fmla.2d v12, v8, v11
  adds x1, x5, x1
  cinc x5, x9, hs
  fsub.2d v13, v6, v12
  fmla.2d v13, v8, v11
  mul x9, x12, x6
  add.2d v3, v3, v12
  add.2d v7, v7, v13
  ucvtf.2d v8, v10
  umulh x6, x12, x6
  mov x10, #58856
  movk x10, #14953, lsl 16
  adds x5, x9, x5
  cinc x6, x6, hs
  movk x10, #15155, lsl 32
  movk x10, #17181, lsl 48
  dup.2d v10, x10
  adds x2, x5, x2
  cinc x5, x6, hs
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  add x3, x3, x5
  fmla.2d v12, v8, v10
  add.2d v0, v0, v11
  mov x5, #61005
  add.2d v9, v9, v12
  mov x6, #35392
  movk x6, #12477, lsl 16
  movk x5, #58262, lsl 16
  movk x6, #56780, lsl 32
  movk x6, #17142, lsl 48
  movk x5, #32851, lsl 32
  dup.2d v10, x6
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  movk x5, #11582, lsl 48
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  add.2d v1, v1, v11
  mov x6, #37581
  add.2d v0, v0, v12
  mov x9, #9848
  movk x6, #43836, lsl 16
  movk x9, #54501, lsl 16
  movk x9, #31540, lsl 32
  movk x9, #17170, lsl 48
  movk x6, #36286, lsl 32
  dup.2d v10, x9
  mov.16b v11, v5
  fmla.2d v11, v8, v10
  movk x6, #51783, lsl 48
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  mov x9, #10899
  add.2d v2, v2, v11
  add.2d v1, v1, v12
  mov x10, #9584
  movk x9, #30709, lsl 16
  movk x10, #63883, lsl 16
  movk x10, #18253, lsl 32
  movk x9, #61551, lsl 32
  movk x10, #17190, lsl 48
  dup.2d v10, x10
  mov.16b v11, v5
  movk x9, #45784, lsl 48
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  fmla.2d v12, v8, v10
  mov x10, #36612
  add.2d v7, v7, v11
  add.2d v2, v2, v12
  movk x10, #63402, lsl 16
  mov x11, #51712
  movk x11, #16093, lsl 16
  movk x11, #30633, lsl 32
  movk x10, #47623, lsl 32
  movk x11, #17068, lsl 48
  dup.2d v10, x11
  mov.16b v11, v5
  movk x10, #9430, lsl 48
  fmla.2d v11, v8, v10
  fsub.2d v12, v6, v11
  mul x11, x5, x7
  fmla.2d v12, v8, v10
  add.2d v3, v3, v11
  add.2d v7, v7, v12
  umulh x5, x5, x7
  ucvtf.2d v4, v4
  mov x12, #34724
  adds x8, x11, x8
  cinc x5, x5, hs
  movk x12, #40393, lsl 16
  movk x12, #23752, lsl 32
  movk x12, #17184, lsl 48
  mul x11, x6, x7
  dup.2d v8, x12
  mov.16b v10, v5
  fmla.2d v10, v4, v8
  umulh x6, x6, x7
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v8
  adds x5, x11, x5
  cinc x6, x6, hs
  add.2d v0, v0, v10
  add.2d v8, v9, v11
  mov x11, #25532
  adds x0, x5, x0
  cinc x5, x6, hs
  movk x11, #31025, lsl 16
  movk x11, #10002, lsl 32
  movk x11, #17199, lsl 48
  mul x6, x9, x7
  dup.2d v9, x11
  mov.16b v10, v5
  umulh x9, x9, x7
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  adds x5, x6, x5
  cinc x6, x9, hs
  add.2d v1, v1, v10
  add.2d v0, v0, v11
  adds x1, x5, x1
  cinc x5, x6, hs
  mov x6, #18830
  movk x6, #2465, lsl 16
  movk x6, #36348, lsl 32
  mul x9, x10, x7
  movk x6, #17194, lsl 48
  dup.2d v9, x6
  mov.16b v10, v5
  umulh x6, x10, x7
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  adds x5, x9, x5
  cinc x6, x6, hs
  fmla.2d v11, v4, v9
  add.2d v2, v2, v10
  add.2d v1, v1, v11
  adds x2, x5, x2
  cinc x5, x6, hs
  mov x6, #21566
  movk x6, #43708, lsl 16
  movk x6, #57685, lsl 32
  add x3, x3, x5
  movk x6, #17185, lsl 48
  dup.2d v9, x6
  mov x5, #65535
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  fsub.2d v11, v6, v10
  movk x5, #61439, lsl 16
  fmla.2d v11, v4, v9
  add.2d v7, v7, v10
  movk x5, #62867, lsl 32
  add.2d v2, v2, v11
  mov x6, #3072
  movk x6, #8058, lsl 16
  movk x5, #49889, lsl 48
  movk x6, #46097, lsl 32
  movk x6, #17047, lsl 48
  dup.2d v9, x6
  mul x5, x5, x8
  mov.16b v10, v5
  fmla.2d v10, v4, v9
  mov x6, #1
  fsub.2d v11, v6, v10
  fmla.2d v11, v4, v9
  add.2d v3, v3, v10
  movk x6, #61440, lsl 16
  add.2d v4, v7, v11
  mov x7, #65535
  movk x6, #62867, lsl 32
  movk x7, #61439, lsl 16
  movk x7, #62867, lsl 32
  movk x7, #1, lsl 48
  movk x6, #17377, lsl 48
  umov x9, v8.d[0]
  umov x10, v8.d[1]
  mul x9, x9, x7
  mov x11, #28817
  mul x7, x10, x7
  and x9, x9, x4
  movk x11, #31161, lsl 16
  and x4, x7, x4
  ins v7.d[0], x9
  ins v7.d[1], x4
  ucvtf.2d v7, v7
  movk x11, #59464, lsl 32
  mov x4, #16
  movk x4, #22847, lsl 32
  movk x4, #17151, lsl 48
  movk x11, #10291, lsl 48
  dup.2d v9, x4
  mov.16b v10, v5
  mov x4, #22621
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v9
  movk x4, #33153, lsl 16
  add.2d v0, v0, v10
  add.2d v8, v8, v11
  movk x4, #17846, lsl 32
  mov x7, #20728
  movk x7, #23588, lsl 16
  movk x7, #7790, lsl 32
  movk x4, #47184, lsl 48
  movk x7, #17170, lsl 48
  dup.2d v9, x7
  mov.16b v10, v5
  mov x7, #41001
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  movk x7, #57649, lsl 16
  fmla.2d v11, v7, v9
  add.2d v1, v1, v10
  add.2d v0, v0, v11
  movk x7, #20082, lsl 32
  mov x9, #16000
  movk x9, #53891, lsl 16
  movk x9, #5509, lsl 32
  movk x7, #12388, lsl 48
  movk x9, #17144, lsl 48
  dup.2d v9, x9
  mul x9, x6, x5
  mov.16b v10, v5
  fmla.2d v10, v7, v9
  fsub.2d v11, v6, v10
  umulh x6, x6, x5
  fmla.2d v11, v7, v9
  add.2d v2, v2, v10
  cmn x9, x8
  cinc x6, x6, hs
  add.2d v9, v1, v11
  mov x8, #46800
  movk x8, #2568, lsl 16
  mul x9, x11, x5
  movk x8, #1335, lsl 32
  movk x8, #17188, lsl 48
  dup.2d v1, x8
  umulh x8, x11, x5
  mov.16b v10, v5
  fmla.2d v10, v7, v1
  adds x6, x9, x6
  cinc x8, x8, hs
  fsub.2d v11, v6, v10
  fmla.2d v11, v7, v1
  add.2d v1, v4, v10
  adds x0, x6, x0
  cinc x6, x8, hs
  add.2d v4, v2, v11
  mov x8, #39040
  movk x8, #14704, lsl 16
  mul x9, x4, x5
  movk x8, #12839, lsl 32
  movk x8, #17096, lsl 48
  umulh x4, x4, x5
  dup.2d v2, x8
  mov.16b v5, v5
  fmla.2d v5, v7, v2
  adds x6, x9, x6
  cinc x4, x4, hs
  fsub.2d v6, v6, v5
  fmla.2d v6, v7, v2
  adds x1, x6, x1
  cinc x4, x4, hs
  add.2d v5, v3, v5
  add.2d v6, v1, v6
  ssra.2d v0, v8, #52
  mul x6, x7, x5
  ssra.2d v9, v0, #52
  ssra.2d v4, v9, #52
  ssra.2d v6, v4, #52
  umulh x5, x7, x5
  ssra.2d v5, v6, #52
  ushr.2d v1, v9, #12
  adds x4, x6, x4
  cinc x5, x5, hs
  ushr.2d v2, v4, #24
  ushr.2d v3, v6, #36
  sli.2d v0, v9, #52
  adds x2, x4, x2
  cinc x4, x5, hs
  sli.2d v1, v4, #40
  sli.2d v2, v6, #28
  sli.2d v3, v5, #16
  add x3, x3, x4
