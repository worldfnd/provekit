// GENERATED FILE, DO NOT EDIT!
// in("x0") a[0], in("x1") a[1], in("x2") a[2], in("x3") a[3],
// in("x4") b[0], in("x5") b[1], in("x6") b[2], in("x7") b[3],
// in("x8") table,
// in("v0") av[0], in("v1") av[1], in("v2") av[2], in("v3") av[3],
// in("v4") bv[0], in("v5") bv[1], in("v6") bv[2], in("v7") bv[3],
// lateout("x0") out[0], lateout("x1") out[1], lateout("x2") out[2], lateout("x3") out[3],
// lateout("v0") outv[0], lateout("v1") outv[1], lateout("v2") outv[2], lateout("v3") outv[3],
// lateout("x4") _, lateout("x5") _, lateout("x6") _, lateout("x7") _, lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _, lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _, lateout("x16") _, lateout("x17") _, lateout("x20") _, lateout("x21") _, lateout("x22") _, lateout("x23") _, lateout("x24") _, lateout("v4") _, lateout("v5") _, lateout("v6") _, lateout("v7") _, lateout("v8") _, lateout("v9") _, lateout("v10") _, lateout("v11") _, lateout("v12") _, lateout("v13") _, lateout("v14") _, lateout("v15") _, lateout("v16") _, lateout("v17") _, lateout("v18") _, lateout("v19") _, lateout("v20") _, lateout("v21") _, lateout("v22") _, lateout("v23") _, lateout("v24") _
  mov x9, #4503599627370495
  dup.2d v8, x9
  mov x10, #5075556780046548992
  dup.2d v9, x10
  mov x10, #1
  mov x11, #0
  movk x10, #18032, lsl 48
  dup.2d v10, x10
  shl.2d v11, v1, #14
  shl.2d v12, v2, #26
  shl.2d v13, v3, #38
  adds x10, x0, x2
  adcs x12, x1, x3
  csetm x13, hs
  ushr.2d v3, v3, #14
  shl.2d v14, v0, #2
  usra.2d v11, v0, #50
  usra.2d v12, v1, #38
  usra.2d v13, v2, #26
  and.16b v0, v14, v8
  adds x14, x4, x6
  adcs x15, x5, x7
  csetm x16, hs
  and.16b v1, v11, v8
  and.16b v2, v12, v8
  and.16b v11, v13, v8
  shl.2d v12, v5, #14
  shl.2d v13, v6, #26
  and x17, x14, x13
  shl.2d v14, v7, #38
  ushr.2d v7, v7, #14
  shl.2d v15, v4, #2
  usra.2d v12, v4, #50
  usra.2d v13, v5, #38
  usra.2d v14, v6, #26
  and x20, x15, x13
  and.16b v4, v15, v8
  and.16b v5, v12, v8
  and.16b v6, v13, v8
  and.16b v12, v14, v8
  mov x21, #13605374474286268416
  and x22, x10, x16
  dup.2d v13, x21
  mov x21, #6440147467139809280
  dup.2d v14, x21
  mov x21, #3688448094816436224
  dup.2d v15, x21
  and x21, x12, x16
  mov x23, #9209861237972664320
  dup.2d v16, x23
  mov x23, #12218265789056155648
  dup.2d v17, x23
  mov x23, #17739678932212383744
  dup.2d v18, x23
  and x13, x13, x16
  mov x16, #2301339409586323456
  dup.2d v19, x16
  mov x16, #7822752552742551552
  dup.2d v20, x16
  mov x16, #5071053180419178496
  lsr x13, x13, #63
  dup.2d v21, x16
  mov x16, #16352570246982270976
  dup.2d v22, x16
  ucvtf.2d v0, v0
  ucvtf.2d v1, v1
  ucvtf.2d v2, v2
  adds x16, x17, x22
  adcs x17, x20, x21
  adc x13, x13, x11
  ucvtf.2d v11, v11
  ucvtf.2d v3, v3
  ucvtf.2d v4, v4
  ucvtf.2d v5, v5
  ucvtf.2d v6, v6
  mul x20, x0, x4
  ucvtf.2d v12, v12
  ucvtf.2d v7, v7
  mov.16b v23, v9
  fmla.2d v23, v0, v4
  fsub.2d v24, v10, v23
  fmla.2d v24, v0, v4
  umulh x21, x0, x4
  add.2d v15, v15, v23
  add.2d v13, v13, v24
  mov.16b v23, v9
  fmla.2d v23, v0, v5
  fsub.2d v24, v10, v23
  mul x22, x1, x4
  fmla.2d v24, v0, v5
  add.2d v17, v17, v23
  add.2d v15, v15, v24
  mov.16b v23, v9
  fmla.2d v23, v0, v6
  umulh x4, x1, x4
  fsub.2d v24, v10, v23
  fmla.2d v24, v0, v6
  add.2d v19, v19, v23
  add.2d v17, v17, v24
  mov.16b v23, v9
  fmla.2d v23, v0, v12
  adds x21, x22, x21
  cinc x4, x4, hs
  fsub.2d v24, v10, v23
  fmla.2d v24, v0, v12
  add.2d v21, v21, v23
  add.2d v19, v19, v24
  mov.16b v23, v9
  mul x22, x0, x5
  fmla.2d v23, v0, v7
  fsub.2d v24, v10, v23
  fmla.2d v24, v0, v7
  add.2d v0, v22, v23
  add.2d v21, v21, v24
  mov.16b v22, v9
  umulh x0, x0, x5
  fmla.2d v22, v1, v4
  fsub.2d v23, v10, v22
  fmla.2d v23, v1, v4
  add.2d v17, v17, v22
  add.2d v15, v15, v23
  mul x23, x1, x5
  mov.16b v22, v9
  fmla.2d v22, v1, v5
  fsub.2d v23, v10, v22
  fmla.2d v23, v1, v5
  add.2d v19, v19, v22
  add.2d v17, v17, v23
  umulh x1, x1, x5
  mov.16b v22, v9
  fmla.2d v22, v1, v6
  fsub.2d v23, v10, v22
  fmla.2d v23, v1, v6
  add.2d v21, v21, v22
  adds x0, x23, x0
  cinc x1, x1, hs
  add.2d v19, v19, v23
  mov.16b v22, v9
  fmla.2d v22, v1, v12
  fsub.2d v23, v10, v22
  fmla.2d v23, v1, v12
  adds x5, x21, x22
  adcs x0, x4, x0
  cinc x1, x1, hs
  add.2d v0, v0, v22
  add.2d v21, v21, v23
  mov.16b v22, v9
  fmla.2d v22, v1, v7
  fsub.2d v23, v10, v22
  fmla.2d v23, v1, v7
  mul x4, x2, x6
  add.2d v1, v20, v22
  add.2d v0, v0, v23
  mov.16b v20, v9
  fmla.2d v20, v2, v4
  fsub.2d v22, v10, v20
  umulh x21, x2, x6
  fmla.2d v22, v2, v4
  add.2d v19, v19, v20
  add.2d v17, v17, v22
  mov.16b v20, v9
  fmla.2d v20, v2, v5
  fsub.2d v22, v10, v20
  mul x22, x3, x6
  fmla.2d v22, v2, v5
  add.2d v20, v21, v20
  add.2d v19, v19, v22
  mov.16b v21, v9
  fmla.2d v21, v2, v6
  umulh x6, x3, x6
  fsub.2d v22, v10, v21
  fmla.2d v22, v2, v6
  add.2d v0, v0, v21
  add.2d v20, v20, v22
  mov.16b v21, v9
  fmla.2d v21, v2, v12
  adds x21, x22, x21
  cinc x6, x6, hs
  fsub.2d v22, v10, v21
  fmla.2d v22, v2, v12
  add.2d v1, v1, v21
  add.2d v0, v0, v22
  mov.16b v21, v9
  mul x22, x2, x7
  fmla.2d v21, v2, v7
  fsub.2d v22, v10, v21
  fmla.2d v22, v2, v7
  add.2d v2, v18, v21
  add.2d v1, v1, v22
  umulh x2, x2, x7
  mov.16b v18, v9
  fmla.2d v18, v11, v4
  fsub.2d v21, v10, v18
  fmla.2d v21, v11, v4
  add.2d v18, v20, v18
  add.2d v19, v19, v21
  mul x23, x3, x7
  mov.16b v20, v9
  fmla.2d v20, v11, v5
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v5
  add.2d v0, v0, v20
  umulh x3, x3, x7
  add.2d v18, v18, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v6
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v6
  add.2d v1, v1, v20
  adds x2, x23, x2
  cinc x3, x3, hs
  add.2d v0, v0, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v12
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v12
  adds x7, x21, x22
  adcs x2, x6, x2
  cinc x3, x3, hs
  add.2d v2, v2, v20
  add.2d v1, v1, v21
  mov.16b v20, v9
  fmla.2d v20, v11, v7
  fsub.2d v21, v10, v20
  fmla.2d v21, v11, v7
  mul x6, x10, x14
  add.2d v11, v16, v20
  add.2d v2, v2, v21
  mov.16b v16, v9
  fmla.2d v16, v3, v4
  fsub.2d v20, v10, v16
  umulh x21, x10, x14
  fmla.2d v20, v3, v4
  add.2d v0, v0, v16
  add.2d v4, v18, v20
  mov.16b v16, v9
  fmla.2d v16, v3, v5
  mul x22, x12, x14
  fsub.2d v18, v10, v16
  fmla.2d v18, v3, v5
  add.2d v1, v1, v16
  add.2d v0, v0, v18
  mov.16b v5, v9
  fmla.2d v5, v3, v6
  umulh x14, x12, x14
  fsub.2d v16, v10, v5
  fmla.2d v16, v3, v6
  add.2d v2, v2, v5
  add.2d v1, v1, v16
  mov.16b v5, v9
  adds x21, x22, x21
  cinc x14, x14, hs
  fmla.2d v5, v3, v12
  fsub.2d v6, v10, v5
  fmla.2d v6, v3, v12
  add.2d v5, v11, v5
  add.2d v2, v2, v6
  mov.16b v6, v9
  mul x22, x10, x15
  fmla.2d v6, v3, v7
  fsub.2d v11, v10, v6
  fmla.2d v11, v3, v7
  add.2d v3, v14, v6
  add.2d v5, v5, v11
  umulh x10, x10, x15
  usra.2d v15, v13, #52
  usra.2d v17, v15, #52
  usra.2d v19, v17, #52
  usra.2d v4, v19, #52
  and.16b v6, v13, v8
  and.16b v7, v15, v8
  mul x23, x12, x15
  and.16b v11, v17, v8
  and.16b v8, v19, v8
  ucvtf.2d v6, v6
  mov x24, #37864
  movk x24, #1815, lsl 16
  umulh x12, x12, x15
  movk x24, #28960, lsl 32
  movk x24, #17153, lsl 48
  dup.2d v12, x24
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  adds x10, x23, x10
  cinc x12, x12, hs
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v0, v0, v13
  add.2d v4, v4, v14
  mov x15, #46128
  movk x15, #29964, lsl 16
  adds x21, x21, x22
  adcs x10, x14, x10
  cinc x12, x12, hs
  movk x15, #7587, lsl 32
  movk x15, #17161, lsl 48
  dup.2d v12, x15
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  adds x10, x10, x16
  adcs x12, x12, x17
  adc x13, x13, x11
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v1, v1, v13
  add.2d v0, v0, v14
  mov x14, #52826
  movk x14, #57790, lsl 16
  subs x6, x6, x20
  sbcs x15, x21, x5
  sbcs x10, x10, x0
  sbcs x12, x12, x1
  sbcs x13, x13, x11
  movk x14, #55431, lsl 32
  movk x14, #17196, lsl 48
  dup.2d v12, x14
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  subs x6, x6, x4
  sbcs x14, x15, x7
  sbcs x10, x10, x2
  sbcs x12, x12, x3
  sbcs x13, x13, x11
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v2, v2, v13
  add.2d v1, v1, v14
  mov x15, #31276
  movk x15, #21262, lsl 16
  adds x0, x0, x6
  adcs x1, x1, x14
  adcs x4, x4, x10
  adcs x6, x7, x12
  adcs x2, x2, x13
  adc x3, x3, x11
  movk x15, #2304, lsl 32
  movk x15, #17182, lsl 48
  dup.2d v12, x15
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  ldp x7, x10, [x8, #0]
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v5, v5, v13
  add.2d v2, v2, v14
  mov x11, #28672
  mul x12, x20, x7
  movk x11, #24515, lsl 16
  movk x11, #54929, lsl 32
  movk x11, #17064, lsl 48
  dup.2d v12, x11
  mov.16b v13, v9
  fmla.2d v13, v6, v12
  umulh x7, x20, x7
  fsub.2d v14, v10, v13
  fmla.2d v14, v6, v12
  add.2d v3, v3, v13
  add.2d v5, v5, v14
  ucvtf.2d v6, v7
  mul x11, x20, x10
  mov x13, #44768
  movk x13, #51919, lsl 16
  movk x13, #6346, lsl 32
  movk x13, #17133, lsl 48
  dup.2d v7, x13
  mov.16b v12, v9
  umulh x10, x20, x10
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v0, v0, v12
  add.2d v4, v4, v13
  ldp x13, x14, [x8, #16]
  mov x15, #47492
  movk x15, #23630, lsl 16
  movk x15, #49985, lsl 32
  movk x15, #17168, lsl 48
  dup.2d v7, x15
  mov.16b v12, v9
  mul x15, x20, x13
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v1, v1, v12
  add.2d v0, v0, v13
  umulh x13, x20, x13
  mov x16, #57936
  movk x16, #54828, lsl 16
  movk x16, #18292, lsl 32
  movk x16, #17197, lsl 48
  dup.2d v7, x16
  mul x16, x20, x14
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v2, v2, v12
  add.2d v1, v1, v13
  umulh x14, x20, x14
  mov x17, #17708
  movk x17, #43915, lsl 16
  movk x17, #64348, lsl 32
  movk x17, #17188, lsl 48
  dup.2d v7, x17
  adds x7, x11, x7
  adcs x10, x15, x10
  adcs x11, x16, x13
  cinc x13, x14, hs
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v5, v5, v12
  add.2d v2, v2, v13
  adds x1, x1, x12
  adcs x4, x4, x7
  adcs x6, x6, x10
  adcs x2, x2, x11
  adc x3, x3, x13
  mov x7, #29184
  movk x7, #20789, lsl 16
  movk x7, #19197, lsl 32
  movk x7, #17083, lsl 48
  dup.2d v7, x7
  ldp x7, x10, [x8, #32]
  mov.16b v12, v9
  fmla.2d v12, v6, v7
  fsub.2d v13, v10, v12
  fmla.2d v13, v6, v7
  add.2d v3, v3, v12
  add.2d v5, v5, v13
  mul x11, x5, x7
  ucvtf.2d v6, v11
  mov x12, #58856
  movk x12, #14953, lsl 16
  movk x12, #15155, lsl 32
  movk x12, #17181, lsl 48
  umulh x7, x5, x7
  dup.2d v7, x12
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  mul x12, x5, x10
  add.2d v0, v0, v11
  add.2d v4, v4, v12
  mov x13, #35392
  movk x13, #12477, lsl 16
  movk x13, #56780, lsl 32
  movk x13, #17142, lsl 48
  umulh x10, x5, x10
  dup.2d v7, x13
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  ldp x13, x14, [x8, #48]
  add.2d v1, v1, v11
  add.2d v0, v0, v12
  mov x15, #9848
  movk x15, #54501, lsl 16
  movk x15, #31540, lsl 32
  movk x15, #17170, lsl 48
  mul x16, x5, x13
  dup.2d v7, x15
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  umulh x13, x5, x13
  add.2d v2, v2, v11
  add.2d v1, v1, v12
  mov x15, #9584
  movk x15, #63883, lsl 16
  movk x15, #18253, lsl 32
  movk x15, #17190, lsl 48
  mul x17, x5, x14
  dup.2d v7, x15
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  umulh x5, x5, x14
  add.2d v5, v5, v11
  add.2d v2, v2, v12
  mov x14, #51712
  movk x14, #16093, lsl 16
  movk x14, #30633, lsl 32
  adds x7, x12, x7
  adcs x10, x16, x10
  adcs x12, x17, x13
  cinc x5, x5, hs
  movk x14, #17068, lsl 48
  dup.2d v7, x14
  mov.16b v11, v9
  fmla.2d v11, v6, v7
  fsub.2d v12, v10, v11
  fmla.2d v12, v6, v7
  ldp x13, x14, [x8, #64]
  add.2d v3, v3, v11
  add.2d v5, v5, v12
  ucvtf.2d v6, v8
  mov x15, #34724
  movk x15, #40393, lsl 16
  mul x16, x0, x13
  movk x15, #23752, lsl 32
  movk x15, #17184, lsl 48
  dup.2d v7, x15
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  umulh x13, x0, x13
  fmla.2d v11, v6, v7
  add.2d v0, v0, v8
  add.2d v4, v4, v11
  mov x15, #25532
  movk x15, #31025, lsl 16
  mul x17, x0, x14
  movk x15, #10002, lsl 32
  movk x15, #17199, lsl 48
  dup.2d v7, x15
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  fsub.2d v11, v10, v8
  umulh x14, x0, x14
  fmla.2d v11, v6, v7
  add.2d v1, v1, v8
  add.2d v0, v0, v11
  mov x15, #18830
  movk x15, #2465, lsl 16
  ldp x20, x21, [x8, #80]
  movk x15, #36348, lsl 32
  movk x15, #17194, lsl 48
  dup.2d v7, x15
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  mul x15, x0, x20
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v2, v2, v8
  add.2d v1, v1, v11
  mov x22, #21566
  movk x22, #43708, lsl 16
  umulh x20, x0, x20
  movk x22, #57685, lsl 32
  movk x22, #17185, lsl 48
  dup.2d v7, x22
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  mul x22, x0, x21
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v5, v5, v8
  add.2d v2, v2, v11
  mov x23, #3072
  movk x23, #8058, lsl 16
  umulh x0, x0, x21
  movk x23, #46097, lsl 32
  movk x23, #17047, lsl 48
  dup.2d v7, x23
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  adds x13, x17, x13
  adcs x14, x15, x14
  adcs x15, x22, x20
  cinc x0, x0, hs
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v3, v3, v8
  add.2d v5, v5, v11
  mov x17, #65535
  movk x17, #61439, lsl 16
  adds x11, x11, x16
  adcs x7, x7, x13
  adcs x10, x10, x14
  adcs x12, x12, x15
  adc x0, x5, x0
  movk x17, #62867, lsl 32
  movk x17, #1, lsl 48
  umov x5, v4.d[0]
  umov x13, v4.d[1]
  mul x5, x5, x17
  adds x1, x1, x11
  adcs x4, x4, x7
  adcs x6, x6, x10
  adcs x2, x2, x12
  adc x0, x3, x0
  mul x3, x13, x17
  and x5, x5, x9
  and x3, x3, x9
  ins v6.d[0], x5
  ins v6.d[1], x3
  ucvtf.2d v6, v6
  ldr x3, [x8, #128]
  mov x5, #16
  movk x5, #22847, lsl 32
  movk x5, #17151, lsl 48
  dup.2d v7, x5
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  mul x3, x3, x1
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v0, v0, v8
  add.2d v4, v4, v11
  mov x5, #20728
  ldp x7, x9, [x8, #96]
  movk x5, #23588, lsl 16
  movk x5, #7790, lsl 32
  movk x5, #17170, lsl 48
  dup.2d v7, x5
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  ldp x5, x8, [x8, #112]
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v1, v1, v8
  add.2d v0, v0, v11
  mov x10, #16000
  umulh x7, x3, x7
  movk x10, #53891, lsl 16
  movk x10, #5509, lsl 32
  movk x10, #17144, lsl 48
  dup.2d v7, x10
  mov.16b v8, v9
  fmla.2d v8, v6, v7
  mul x10, x3, x9
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v7
  add.2d v2, v2, v8
  add.2d v7, v1, v11
  mov x11, #46800
  umulh x9, x3, x9
  movk x11, #2568, lsl 16
  movk x11, #1335, lsl 32
  movk x11, #17188, lsl 48
  dup.2d v1, x11
  mov.16b v8, v9
  mul x11, x3, x5
  fmla.2d v8, v6, v1
  fsub.2d v11, v10, v8
  fmla.2d v11, v6, v1
  add.2d v1, v5, v8
  add.2d v5, v2, v11
  mov x12, #39040
  umulh x5, x3, x5
  movk x12, #14704, lsl 16
  movk x12, #12839, lsl 32
  movk x12, #17096, lsl 48
  dup.2d v2, x12
  mov.16b v8, v9
  mul x12, x3, x8
  fmla.2d v8, v6, v2
  fsub.2d v9, v10, v8
  fmla.2d v9, v6, v2
  add.2d v6, v3, v8
  add.2d v8, v1, v9
  ssra.2d v0, v4, #52
  umulh x3, x3, x8
  ssra.2d v7, v0, #52
  ssra.2d v5, v7, #52
  ssra.2d v8, v5, #52
  ssra.2d v6, v8, #52
  ushr.2d v1, v7, #12
  cmp x1, #1
  adcs x1, x4, x10
  adcs x4, x6, x11
  adcs x2, x2, x12
  cinc x6, x0, hs
  ushr.2d v2, v5, #24
  ushr.2d v3, v8, #36
  sli.2d v0, v7, #52
  sli.2d v1, v5, #40
  sli.2d v2, v8, #28
  sli.2d v3, v6, #16
  adds x0, x1, x7
  adcs x1, x4, x9
  adcs x2, x2, x5
  adc x3, x6, x3
